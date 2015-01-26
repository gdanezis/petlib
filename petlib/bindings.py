#!/usr/bin/env python

import os
import cffi


if os.name == "nt":
    # WIN: libraries=["libeay32"], include_dirs=[r"...\pyopenssl"]
    # Ensure you compile with a 64bit lib (run vcvarsx86_amd64.bat)
    libraries=["libeay32"]
    include_dirs=[r"."]
    extra_compile_args = []

    # if "VCINSTALLDIR" not in os.environ:
    #     raise Exception(r"Cannot find the Visual Studio %VCINSTALLDIR% variable. Ensure you ran the appropriate vcvars.bat script.")

    # if "OPENSSL_CONF" not in os.environ:
    #     raise Exception(r"Cannot find the Visual Studio %OPENSSL_CONF% variable. Ensure you install OpenSSL for Windows.")        

    openssl_conf = os.environ["OPENSSL_CONF"]
    openssl_bin, conf_name = os.path.split(openssl_conf)
    openssl_base, bin_name = os.path.split(openssl_bin)
    assert bin_name == "bin"
    include_dirs += [os.path.join(openssl_base, "include")]
    library_dirs = [openssl_base, os.path.join(openssl_base, "lib")]

    print("Windows Library directories")
    print(library_dirs)

else:
    ## Asume we are running on a posix system
    # LINUX: libraries=["crypto"], extra_compile_args=['-Wno-deprecated-declarations']
    libraries=["crypto"]
    extra_compile_args=['-Wno-deprecated-declarations']
    include_dirs=[]
    library_dirs=[]

_FFI = cffi.FFI()

_FFI.cdef("""

/* 
    Generic OpenSSL functions.
*/ 

void OPENSSL_free(void*);
 
 // The constant-time compare functions
 int CRYPTO_memcmp(const void *a, const void *b, size_t len);


/* 
    ECC OpenSSL functions.
*/

typedef enum {
    /* values as defined in X9.62 (ECDSA) and elsewhere */
    POINT_CONVERSION_COMPRESSED = 2,
    POINT_CONVERSION_UNCOMPRESSED = 4,
    POINT_CONVERSION_HYBRID = 6
} point_conversion_form_t;

typedef ... EC_GROUP;
typedef ... EC_POINT;
typedef ... BN_CTX;
typedef ... BIGNUM;
typedef ... BN_GENCB;


EC_GROUP *EC_GROUP_new_by_curve_name(int nid);
void EC_GROUP_free(EC_GROUP* x);
void EC_GROUP_clear_free(EC_GROUP *);

int EC_GROUP_get_curve_GFp(const EC_GROUP *group, BIGNUM *p, BIGNUM *a, BIGNUM *b, BN_CTX *ctx);

int EC_GROUP_cmp(const EC_GROUP *a, const EC_GROUP *b, BN_CTX *ctx);
const EC_POINT *EC_GROUP_get0_generator(const EC_GROUP *);
int EC_GROUP_get_order(const EC_GROUP *, BIGNUM *order, BN_CTX *);
int EC_GROUP_get_cofactor(const EC_GROUP *, BIGNUM *cofactor, BN_CTX *);
int EC_GROUP_get_curve_name(const EC_GROUP *group);

EC_POINT *EC_POINT_new(const EC_GROUP *);
void EC_POINT_free(EC_POINT *);
void EC_POINT_clear_free(EC_POINT *);
int EC_POINT_copy(EC_POINT *, const EC_POINT *);
EC_POINT *EC_POINT_dup(const EC_POINT *, const EC_GROUP *);

int EC_POINT_set_to_infinity(const EC_GROUP *, EC_POINT *);
int EC_POINT_add(const EC_GROUP *, EC_POINT *r, const EC_POINT *a, const EC_POINT *b, BN_CTX *);
int EC_POINT_dbl(const EC_GROUP *, EC_POINT *r, const EC_POINT *a, BN_CTX *);
int EC_POINT_invert(const EC_GROUP *, EC_POINT *, BN_CTX *);

int EC_POINT_is_at_infinity(const EC_GROUP *, const EC_POINT *);
int EC_POINT_is_on_curve(const EC_GROUP *, const EC_POINT *, BN_CTX *);

int EC_POINT_cmp(const EC_GROUP *, const EC_POINT *a, const EC_POINT *b, BN_CTX *);

int EC_POINT_make_affine(const EC_GROUP *, EC_POINT *, BN_CTX *);
int EC_POINTs_make_affine(const EC_GROUP *, size_t num, EC_POINT *[], BN_CTX *);


int EC_POINTs_mul(const EC_GROUP *, EC_POINT *r, const BIGNUM *, size_t num, const EC_POINT *[], const BIGNUM *[], BN_CTX *);
int EC_POINT_mul(const EC_GROUP *, EC_POINT *r, const BIGNUM *, const EC_POINT *, const BIGNUM *, BN_CTX *);

/* EC_GROUP_precompute_mult() stores multiples of generator for faster point multiplication */
int EC_GROUP_precompute_mult(EC_GROUP *, BN_CTX *);
/* EC_GROUP_have_precompute_mult() reports whether such precomputation has been done */
int EC_GROUP_have_precompute_mult(const EC_GROUP *);

int EC_POINT_get_affine_coordinates_GFp(const EC_GROUP *group,
const EC_POINT *p, BIGNUM *x, BIGNUM *y, BN_CTX *ctx);
int EC_POINT_set_compressed_coordinates_GFp(const EC_GROUP *group, EC_POINT *p,
const BIGNUM *x, int y_bit, BN_CTX *ctx);

size_t EC_POINT_point2oct(const EC_GROUP *, const EC_POINT *, point_conversion_form_t form,
                unsigned char *buf, size_t len, BN_CTX *);
int EC_POINT_oct2point(const EC_GROUP *, EC_POINT *,
                const unsigned char *buf, size_t len, BN_CTX *);

typedef struct { 
    int nid;
    const char *comment;
    } EC_builtin_curve;

size_t EC_get_builtin_curves(EC_builtin_curve *r, size_t nitems);

/*
    Big Number (BN) OpenSSL functions.
*/

typedef unsigned int BN_ULONG;

BN_CTX *BN_CTX_new(void);
void    BN_CTX_free(BN_CTX *c);

BIGNUM* BN_new(void);
void    BN_init(BIGNUM *);
void    BN_clear_free(BIGNUM *a);
BIGNUM* BN_copy(BIGNUM *a, const BIGNUM *b);
void    BN_swap(BIGNUM *a, BIGNUM *b);

int     BN_cmp(const BIGNUM *a, const BIGNUM *b);
int     BN_set_word(BIGNUM *a, BN_ULONG w);

void    BN_set_negative(BIGNUM *b, int n);

int     BN_add(BIGNUM *r, const BIGNUM *a, const BIGNUM *b);
int     BN_sub(BIGNUM *r, const BIGNUM *a, const BIGNUM *b);

int     BN_mul(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, BN_CTX *ctx);
int     BN_div(BIGNUM *dv, BIGNUM *rem, const BIGNUM *m, const BIGNUM *d, BN_CTX *ctx);

int     BN_exp(BIGNUM *r, const BIGNUM *a, const BIGNUM *p,BN_CTX *ctx);
int     BN_mod_exp(BIGNUM *r, const BIGNUM *a, const BIGNUM *p, const BIGNUM *m,BN_CTX *ctx);
BIGNUM* BN_mod_inverse(BIGNUM *ret, const BIGNUM *a, const BIGNUM *n,BN_CTX *ctx);

 int    BN_nnmod(BIGNUM *r, const BIGNUM *a, const BIGNUM *m, BN_CTX *ctx);
 int    BN_mod_add(BIGNUM *r, BIGNUM *a, BIGNUM *b, const BIGNUM *m,
                        BN_CTX *ctx);
 int    BN_mod_sub(BIGNUM *r, BIGNUM *a, BIGNUM *b, const BIGNUM *m,
                        BN_CTX *ctx);
 int    BN_mod_mul(BIGNUM *r, BIGNUM *a, BIGNUM *b, const BIGNUM *m,
                        BN_CTX *ctx);

int     bn_num_bytes(BIGNUM * a);
int     BN_num_bits(const BIGNUM *a);
char *  BN_bn2dec(const BIGNUM *a);
char *  BN_bn2hex(const BIGNUM *a);
int     BN_hex2bn(BIGNUM **a, const char *str);
int     BN_dec2bn(BIGNUM **a, const char *str);
BIGNUM* BN_bin2bn(const unsigned char *s,int len,BIGNUM *ret);
int     BN_bn2bin(const BIGNUM *a, unsigned char *to);

int     BN_generate_prime_ex(BIGNUM *ret,int bits,int safe, const BIGNUM *add, 
                        const BIGNUM *rem, BN_GENCB *cb);
int     BN_is_prime_ex(const BIGNUM *p,int nchecks, BN_CTX *ctx, BN_GENCB *cb);

int     BN_rand_range(BIGNUM *rnd, const BIGNUM *range);


int bn_is_odd(BIGNUM * a);
// int BN_is_odd(const BIGNUM *a);


int BN_is_bit_set(const BIGNUM *a, int n);


/* 

    EVP Ciphers 

*/

typedef struct evp_cipher_st
{
    int nid;
    int block_size;
    int key_len; /* Default value for variable length ciphers */
    int iv_len;
    unsigned long flags; /* Various flags */
    ...;
} EVP_CIPHER;

typedef struct evp_cipher_ctx_st
{
    const EVP_CIPHER *cipher;
    int encrypt; /* encrypt or decrypt */
    int buf_len; /* number we have left */
    int num; /* used by cfb/ofb/ctr mode */
    int key_len; /* May change for variable length cipher */
    unsigned long flags; /* Various flags */
    int final_used;
    int block_mask;
    ...;
} EVP_CIPHER_CTX;

const EVP_CIPHER * EVP_aes_128_gcm(void);
const EVP_CIPHER * EVP_aes_192_gcm(void);
const EVP_CIPHER * EVP_aes_256_gcm(void);

typedef ... ENGINE; // Ignore details of the engine.

// Cipher context operations

void EVP_CIPHER_CTX_init(EVP_CIPHER_CTX *a);
int EVP_CIPHER_CTX_cleanup(EVP_CIPHER_CTX *a);
EVP_CIPHER_CTX *EVP_CIPHER_CTX_new(void);
void EVP_CIPHER_CTX_free(EVP_CIPHER_CTX *a);
int EVP_CIPHER_CTX_set_key_length(EVP_CIPHER_CTX *x, int keylen);
int EVP_CIPHER_CTX_set_padding(EVP_CIPHER_CTX *c, int pad);
int EVP_CIPHER_CTX_ctrl(EVP_CIPHER_CTX *ctx, int type, int arg, void *ptr);
int EVP_CIPHER_CTX_rand_key(EVP_CIPHER_CTX *ctx, unsigned char *key);

// Cipher operations

const EVP_CIPHER *EVP_get_cipherbyname(const char *name);

int  EVP_CipherInit_ex(EVP_CIPHER_CTX *ctx,const EVP_CIPHER *cipher, ENGINE *impl,
const unsigned char *key,const unsigned char *iv, int enc);
int  EVP_CipherUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out,
int *outl, const unsigned char *in, int inl);
int  EVP_CipherFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *outm, int *outl);

// The control codes for ciphers

#define EVP_CTRL_INIT ...
#define EVP_CTRL_SET_KEY_LENGTH ...
#define EVP_CTRL_GET_RC2_KEY_BITS ...
#define EVP_CTRL_SET_RC2_KEY_BITS ...
#define EVP_CTRL_GET_RC5_ROUNDS ...
#define EVP_CTRL_SET_RC5_ROUNDS ...
#define EVP_CTRL_RAND_KEY ...
#define EVP_CTRL_PBE_PRF_NID  ...
#define EVP_CTRL_COPY ...
#define EVP_CTRL_GCM_SET_IVLEN  ...
#define EVP_CTRL_GCM_GET_TAG  ...
#define EVP_CTRL_GCM_SET_TAG  ...
#define EVP_CTRL_GCM_SET_IV_FIXED ...
#define EVP_CTRL_GCM_IV_GEN ...
#define EVP_CTRL_CCM_SET_IVLEN  ...
#define EVP_CTRL_CCM_GET_TAG  ...
#define EVP_CTRL_CCM_SET_TAG  ...
#define EVP_CTRL_CCM_SET_L  ...
#define EVP_CTRL_CCM_SET_MSGLEN ...
#define EVP_CTRL_AEAD_TLS1_AAD  ...
#define EVP_CTRL_AEAD_SET_MAC_KEY ...
#define EVP_CTRL_GCM_SET_IV_INV ...

 int EVP_EncryptInit_ex(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type,
                 ENGINE *impl, unsigned char *key, unsigned char *iv);
 int EVP_EncryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out,
                 int *outl, unsigned char *in, int inl);
 int EVP_EncryptFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *out,
                 int *outl);

 int EVP_DecryptInit_ex(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type,
                 ENGINE *impl, unsigned char *key, unsigned char *iv);
 int EVP_DecryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out,
                 int *outl, unsigned char *in, int inl);
 int EVP_DecryptFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *outm,
                 int *outl);

void init_ciphers();
void cleanup_ciphers();

// The HMAC interface


typedef struct { ...; } HMAC_CTX;
typedef ... EVP_MD;

size_t hmac_ctx_size();

int EVP_MD_size(const EVP_MD *md);
int EVP_MD_block_size(const EVP_MD *md);
const EVP_MD *EVP_get_digestbyname(const char *name);


 void HMAC_CTX_init(HMAC_CTX *ctx);

 int HMAC_Init_ex(HMAC_CTX *ctx, const void *key, int key_len,
                                     const EVP_MD *md, ENGINE *impl);
 int HMAC_Update(HMAC_CTX *ctx, const unsigned char *data, int len);
 int HMAC_Final(HMAC_CTX *ctx, unsigned char *md, unsigned int *len);

 void HMAC_CTX_cleanup(HMAC_CTX *ctx);
 

// The ECDSA interface


typedef struct ECDSA_SIG_st
{
    BIGNUM * r;
    BIGNUM * s;
} ECDSA_SIG;

typedef ... EC_KEY; 

 ECDSA_SIG*     ECDSA_SIG_new(void);
 void           ECDSA_SIG_free(ECDSA_SIG *sig);

 ECDSA_SIG*     ECDSA_do_sign(const unsigned char *dgst, int dgst_len,
                                                EC_KEY *eckey);
 int            ECDSA_do_verify(const unsigned char *dgst, int dgst_len,
                                                const ECDSA_SIG *sig, EC_KEY* eckey);
 int            ECDSA_size(const EC_KEY *eckey);


EC_KEY *EC_KEY_new(void);
void EC_KEY_free(EC_KEY *key);

int EC_KEY_set_group(EC_KEY *key, const EC_GROUP *group);
int EC_KEY_set_private_key(EC_KEY *key, const BIGNUM *prv);
int EC_KEY_set_public_key(EC_KEY *key, const EC_POINT *pub);

#define SSLEAY_VERSION ...
const char *SSLeay_version(int type);

""")

_C = _FFI.verify("""
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/ecdsa.h>

#define BN_num_bytes(a) ((BN_num_bits(a)+7)/8)


int bn_num_bytes(BIGNUM * a){
    return BN_num_bytes(a);
}

int bn_is_odd(BIGNUM * a){
    return BN_is_odd(a);
}

size_t hmac_ctx_size(void){
    return sizeof(HMAC_CTX);
}


extern void ERR_load_crypto_strings(void);
extern void OPENSSL_config(void*);
extern void ERR_free_strings(void);

void init_ciphers(void){

    /* Load the human readable error strings for libcrypto */
    ERR_load_crypto_strings();

    /* Load all digest and cipher algorithms */
    OpenSSL_add_all_algorithms();

    /* Load config file, and other important initialisation */
    OPENSSL_config(NULL);

}

void cleanup_ciphers(void){

    /* Removes all digests and ciphers */
    EVP_cleanup();

    /* if you omit the next, a small leak may be left when you make use of the BIO (low level API) for e.g. base64 transformations */
    CRYPTO_cleanup_all_ex_data();

    /* Remove error strings */
    ERR_free_strings();

}

""", libraries=libraries, 
     extra_compile_args=extra_compile_args, 
     include_dirs=include_dirs,
     library_dirs=library_dirs, 
     ext_package='petlib')

_inited = False

def version():
    return str(_FFI.string(_C.SSLeay_version(_C.SSLEAY_VERSION)))

class InitCiphers(object):
    # pylint: disable=global-statement

    def __init__(self):
        global _inited
        self.on = False
        if not _inited:
            _C.init_ciphers()
            _inited = True
            self.on = True

    def __del__(self):
        global _inited
        if _inited and self.on and _C:
            _inited = False
            _C.cleanup_ciphers()

_ciphers = InitCiphers()

def test_double_load():
    _c2 = InitCiphers()
    del _c2
    ## Nothing bad should happen

def test_version():
    print (version())
    assert version()
