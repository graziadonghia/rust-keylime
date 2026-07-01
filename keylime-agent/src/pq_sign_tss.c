/*
 gcc -Wall -O2 -o pq_sign_tss pq_sign_tss.c \
    -I/opt/quantumsafe/build/include \
    -L/opt/quantumsafe/build/lib64 \
    -L/opt/quantumsafe/build/lib \
    -Wl,-rpath=/opt/quantumsafe/build/lib64 \
    -Wl,-rpath=/opt/quantumsafe/build/lib \
    -ltss2-esys -lcrypto
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tss2/tss2_esys.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/crypto.h>

#define PERSISTENT_HANDLE 0x81020004
#define SK_SIZE 128
#define MAX_PAYLOAD_SIZE 1048576

/* All errors MUST go to stderr so they don't corrupt the stdout signature stream */
static void die_ossl(const char *m) { fprintf(stderr, "FATAL: %s\n", m); ERR_print_errors_fp(stderr); exit(1); }

/* --- Tiny DER Builder --- */
typedef struct { unsigned char *p; size_t len; size_t cap; } bb;
static void bb_init(bb *b) { b->p=NULL; b->len=0; b->cap=0; }
static void bb_free(bb *b) { free(b->p); b->p=NULL; b->len=b->cap=0; }
static void bb_reserve(bb *b, size_t add) { if(b->len+add<=b->cap) return; size_t ncap=b->cap?b->cap:256; while(ncap<b->len+add) ncap*=2; b->p=realloc(b->p,ncap); b->cap=ncap; }
static void bb_put(bb *b, const void *data, size_t n) { bb_reserve(b, n); memcpy(b->p + b->len, data, n); b->len += n; }
static void bb_put_u8(bb *b, unsigned char v) { bb_put(b, &v, 1); }
static void der_put_len(bb *b, size_t len) { if (len < 128) { bb_put_u8(b, (unsigned char)len); return; } unsigned char tmp[10]; int n = 0; size_t x = len; while (x) { tmp[n++] = (unsigned char)(x & 0xFF); x >>= 8; } bb_put_u8(b, 0x80 | (unsigned char)n); for (int i = n - 1; i >= 0; i--) bb_put_u8(b, tmp[i]); }
static void der_wrap_tlv(unsigned char tag, const unsigned char *val, size_t vlen, bb *out) { bb_put_u8(out, tag); der_put_len(out, vlen); bb_put(out, val, vlen); }
static void der_put_oid(bb *b, const char *oid_txt) { ASN1_OBJECT *obj = OBJ_txt2obj(oid_txt, 1); unsigned char *der = NULL; int len = i2d_ASN1_OBJECT(obj, &der); bb_put(b, der, (size_t)len); OPENSSL_free(der); ASN1_OBJECT_free(obj); }
static void der_put_int0(bb *b) { unsigned char tlv[3] = { 0x02, 0x01, 0x00 }; bb_put(b, tlv, sizeof(tlv)); }
static void der_put_seq(bb *b, const unsigned char *content, size_t clen) { der_wrap_tlv(0x30, content, clen, b); }

static void build_pkcs8_privkey(bb *out, const unsigned char *raw_sk, size_t sk_len) {
    const char *slhdsa_oid = "2.16.840.1.101.3.4.3.30";
    bb alg, algseq, octet, body; 
    bb_init(&alg); bb_init(&algseq); bb_init(&octet); bb_init(&body);

    der_put_oid(&alg, slhdsa_oid);
    der_put_seq(&algseq, alg.p, alg.len);
    der_wrap_tlv(0x04, raw_sk, sk_len, &octet);

    der_put_int0(&body);
    bb_put(&body, algseq.p, algseq.len);
    bb_put(&body, octet.p, octet.len);

    der_put_seq(out, body.p, body.len);

    bb_free(&alg); bb_free(&algseq); bb_free(&octet); bb_free(&body);
}

int main() {
    OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG, NULL);

    OSSL_PROVIDER *def = OSSL_PROVIDER_load(NULL, "default");
    OSSL_PROVIDER *aur = OSSL_PROVIDER_load(NULL, "aurora");
    if (!aur) die_ossl("Load aurora failed");

    /* 1. Read Payload (the auth_tag) from stdin sent by Rust */
    unsigned char payload[MAX_PAYLOAD_SIZE];
    size_t payload_len = fread(payload, 1, MAX_PAYLOAD_SIZE, stdin);
    if (payload_len == 0) { fprintf(stderr, "No payload received on stdin\n"); return 1; }

    /* 2. Unseal Secret Key from TPM */
    TSS2_RC rc;
    ESYS_CONTEXT *esys_ctx = NULL;
    Esys_Initialize(&esys_ctx, NULL, NULL);

    ESYS_TR object_handle = ESYS_TR_NONE;
    Esys_TR_FromTPMPublic(esys_ctx, PERSISTENT_HANDLE, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, &object_handle);
    Esys_TR_SetAuth(esys_ctx, object_handle, NULL);

    TPM2B_SENSITIVE_DATA *outData = NULL;
    rc = Esys_Unseal(esys_ctx, object_handle, ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE, &outData);
    if (rc != TSS2_RC_SUCCESS || outData == NULL) { fprintf(stderr, "Esys_Unseal failed: 0x%x\n", rc); return 1; }

    mlock(outData->buffer, outData->size);

    /* 3. Wrap to PKCS#8 and Decode */
    bb pkcs8_der; bb_init(&pkcs8_der);
    build_pkcs8_privkey(&pkcs8_der, outData->buffer, SK_SIZE);

    OPENSSL_cleanse(outData->buffer, outData->size);
    munlock(outData->buffer, outData->size);
    Esys_Free(outData);

    const unsigned char *p = pkcs8_der.p;
    EVP_PKEY *pkey = d2i_PrivateKey(EVP_PKEY_NONE, NULL, &p, pkcs8_der.len);

    OPENSSL_cleanse(pkcs8_der.p, pkcs8_der.len);
    bb_free(&pkcs8_der);

    if (!pkey) die_ossl("Failed to decode PKCS#8 Private Key via Aurora");

    /* 4. Generate Signature */
    size_t sig_len = 0;
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    
    if (EVP_DigestSignInit(mdctx, NULL, NULL, NULL, pkey) <= 0) die_ossl("Sign Init failed");
    if (EVP_DigestSign(mdctx, NULL, &sig_len, payload, payload_len) <= 0) die_ossl("Sign length calc failed");
    
    unsigned char *sig = malloc(sig_len);
    if (EVP_DigestSign(mdctx, sig, &sig_len, payload, payload_len) <= 0) die_ossl("Sign failed");

    /* 5. Output raw binary signature to stdout for Rust to capture */
    fwrite(sig, 1, sig_len, stdout);

    free(sig); EVP_MD_CTX_free(mdctx); EVP_PKEY_free(pkey);
    OSSL_PROVIDER_unload(aur); OSSL_PROVIDER_unload(def);
    return 0;
}