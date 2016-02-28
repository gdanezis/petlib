#!/usr/bin/env python

import os
import platform
import cffi


if platform.system() == "Windows":
    # Windows building instructions:
    # * Ensure you compile with a 64bit lib and toolchain 
    #   (run vcvarsx86_amd64.bat)
    # * Ensure the OpenSSL 64 bit lib is on the path.
    #   (PATH=C:\OpenSSL-Win64\bin;%PATH%)
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
    library_dirs = [openssl_base, os.path.join(openssl_base, "lib"), os.path.join(openssl_base, "bin")]

    # print("Windows Library directories:")
    # print(library_dirs)

else:
    ## Asume we are running on a posix system
    # LINUX: libraries=["crypto"], extra_compile_args=['-Wno-deprecated-declarations']
    libraries=[ ]
    extra_compile_args=['-Wno-deprecated-declarations ']
    if platform.system() == "Darwin":
        include_dirs=['../openssl/include']
        # FIXME(ben): not entirely clear to me why I don't seem to
        # have to include /opt/local/lib.
        library_dirs=[]
        link_args = ['../openssl/']
    else:
        include_dirs=['../openssl/include']
        library_dirs=[]
        link_args = ['../openssl/libcrypto.so']

_FFI = cffi.FFI()

# _FFI.set_source(""" """, libraries=libraries, extra_compile_args=extra_compile_args, include_dirs=include_dirs, library_dirs=library_dirs, ext_package='petlib')

_FFI.set_source("petlib._petlib","""

#include <openssl/err.h>
#include <openssl/bn.h>

#include <openssl/bp.h>

#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/ecdsa.h>

// #define BN_num_bytes(a) ((BN_num_bits(a)+7)/8)


int bn_num_bytes(BIGNUM * a){
    return BN_num_bytes(a);
}

int bn_is_odd(BIGNUM * a){
    return BN_is_odd(a);
}

/*
size_t hmac_ctx_size(void){
    return sizeof(HMAC_CTX);
}
*/


// extern void ERR_load_crypto_strings(void);
extern void OPENSSL_config(void*);
extern void ERR_free_strings(void);

void init_ciphers(void){

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
    extra_link_args=link_args)


_FFI.cdef("""

/* 
    Generic OpenSSL functions.
*/ 

void OPENSSL_free(void*);
 
 // The constant-time compare functions
 int CRYPTO_memcmp(const void *a, const void *b, size_t len);

typedef enum foo {
     /* values as defined in X9.62 (ECDSA) and elsewhere */
     POINT_CONVERSION_COMPRESSED = 2,
     POINT_CONVERSION_UNCOMPRESSED = 4,
     POINT_CONVERSION_HYBRID = 6
} point_conversion_form_t;


const char *OpenSSL_version(int type);
# define OPENSSL_VERSION          0
# define OPENSSL_CFLAGS           1
# define OPENSSL_BUILT_ON         2
# define OPENSSL_PLATFORM         3
# define OPENSSL_DIR              4
# define OPENSSL_ENGINES_DIR      5

unsigned long ERR_get_error(void);

/* 
    ECC OpenSSL functions.
*/

typedef ... BIGNUM;

typedef ... EC_GROUP;
typedef ... EC_POINT;
typedef ... BN_CTX;
typedef ... BN_GENCB;


// ECGROUP

EC_GROUP *EC_GROUP_new_by_curve_name(int nid);
void EC_GROUP_free(EC_GROUP* x);
void EC_GROUP_clear_free(EC_GROUP *);
int EC_GROUP_get_curve_GFp(const EC_GROUP *group, BIGNUM *p, BIGNUM *a, BIGNUM *b, BN_CTX *ctx);
int EC_GROUP_cmp(const EC_GROUP *a, const EC_GROUP *b, BN_CTX *ctx);
const EC_POINT *EC_GROUP_get0_generator(const EC_GROUP *);
int EC_GROUP_get_order(const EC_GROUP *, BIGNUM *order, BN_CTX *);
int EC_GROUP_get_cofactor(const EC_GROUP *, BIGNUM *cofactor, BN_CTX *);
int EC_GROUP_get_curve_name(const EC_GROUP *group);

/* EC_GROUP_precompute_mult() stores multiples of generator for faster point multiplication */
int EC_GROUP_precompute_mult(EC_GROUP *, BN_CTX *);
/* EC_GROUP_have_precompute_mult() reports whether such precomputation has been done */
int EC_GROUP_have_precompute_mult(const EC_GROUP *);

typedef struct { 
    int nid;
    const char *comment;
    } EC_builtin_curve;

size_t EC_get_builtin_curves(EC_builtin_curve *r, size_t nitems);

// ECPOINT

EC_POINT *EC_POINT_new(const EC_GROUP *);
void EC_POINT_free(EC_POINT *);
void EC_POINT_clear_free(EC_POINT *);
int EC_POINT_copy(EC_POINT *, const EC_POINT *);
EC_POINT *EC_POINT_dup(const EC_POINT *, const EC_GROUP *);
int EC_POINT_set_to_infinity(const EC_GROUP *, EC_POINT *);
int EC_POINT_add(const EC_GROUP *, EC_POINT *r, const EC_POINT *a, 
                        const EC_POINT *b, BN_CTX *);
int EC_POINT_dbl(const EC_GROUP *, EC_POINT *r, const EC_POINT *a, 
                        BN_CTX *);
int EC_POINT_invert(const EC_GROUP *, EC_POINT *, BN_CTX *);
int EC_POINT_is_at_infinity(const EC_GROUP *, const EC_POINT *);
int EC_POINT_is_on_curve(const EC_GROUP *, const EC_POINT *, BN_CTX *);
int EC_POINT_cmp(const EC_GROUP *, const EC_POINT *a, const EC_POINT *b, 
                        BN_CTX *);
int EC_POINT_make_affine(const EC_GROUP *, EC_POINT *, BN_CTX *);
int EC_POINTs_make_affine(const EC_GROUP *, size_t num, EC_POINT *[], 
                        BN_CTX *);
int EC_POINTs_mul(const EC_GROUP *, EC_POINT *r, const BIGNUM *, size_t num, const EC_POINT *[], const BIGNUM *[], BN_CTX *);
int EC_POINT_mul(const EC_GROUP *, EC_POINT *r, const BIGNUM *, const EC_POINT *, const BIGNUM *, BN_CTX *);
int EC_POINT_get_affine_coordinates_GFp(const EC_GROUP *group,
const EC_POINT *p, BIGNUM *x, BIGNUM *y, BN_CTX *ctx);
int EC_POINT_set_compressed_coordinates_GFp(const EC_GROUP *group, EC_POINT *p,
const BIGNUM *x, int y_bit, BN_CTX *ctx);
size_t EC_POINT_point2oct(const EC_GROUP *, const EC_POINT *, point_conversion_form_t form,
                unsigned char *buf, size_t len, BN_CTX *);
int EC_POINT_oct2point(const EC_GROUP *, EC_POINT *,
                const unsigned char *buf, size_t len, BN_CTX *);

/*
    Big Number (BN) OpenSSL functions.
*/

typedef unsigned int BN_ULONG;

BN_CTX *BN_CTX_new(void);
void    BN_CTX_free(BN_CTX *c);

BIGNUM* BN_new(void);
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
int BN_is_bit_set(const BIGNUM *a, int n);

/* 

    EVP Ciphers 

*/

typedef ... EVP_CIPHER;
typedef ... EVP_CIPHER_CTX;

const EVP_CIPHER * EVP_aes_128_gcm(void);
const EVP_CIPHER * EVP_aes_192_gcm(void);
const EVP_CIPHER * EVP_aes_256_gcm(void);

typedef ... ENGINE; // Ignore details of the engine.

// Cipher context operations

EVP_CIPHER_CTX *EVP_CIPHER_CTX_new(void);
void EVP_CIPHER_CTX_free(EVP_CIPHER_CTX *a);
int EVP_CIPHER_CTX_set_key_length(EVP_CIPHER_CTX *x, int keylen);
int EVP_CIPHER_CTX_set_padding(EVP_CIPHER_CTX *c, int pad);
int EVP_CIPHER_CTX_ctrl(EVP_CIPHER_CTX *ctx, int type, int arg, void *ptr);
int EVP_CIPHER_CTX_rand_key(EVP_CIPHER_CTX *ctx, unsigned char *key);

int EVP_CIPHER_CTX_nid(const EVP_CIPHER_CTX *ctx);
int EVP_CIPHER_CTX_block_size(const EVP_CIPHER_CTX *ctx);
int EVP_CIPHER_CTX_key_length(const EVP_CIPHER_CTX *ctx);
int EVP_CIPHER_CTX_iv_length(const EVP_CIPHER_CTX *ctx);

int EVP_CIPHER_nid(const EVP_CIPHER *cipher);
int EVP_CIPHER_block_size(const EVP_CIPHER *cipher);
int EVP_CIPHER_key_length(const EVP_CIPHER *cipher);
int EVP_CIPHER_iv_length(const EVP_CIPHER *cipher);

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

typedef ... HMAC_CTX;
typedef ... EVP_MD;

int EVP_MD_size(const EVP_MD *md);
int EVP_MD_block_size(const EVP_MD *md);
const EVP_MD *EVP_get_digestbyname(const char *name);

HMAC_CTX* HMAC_CTX_new();
void HMAC_CTX_free(HMAC_CTX *ctx);
int HMAC_Init_ex(HMAC_CTX *ctx, const void *key, int key_len,
                                     const EVP_MD *md, ENGINE *impl);
int HMAC_Update(HMAC_CTX *ctx, const unsigned char *data, int len);
int HMAC_Final(HMAC_CTX *ctx, unsigned char *md, unsigned int *len);
 
// The ECDSA interface

typedef ...  ECDSA_SIG;
typedef ... EC_KEY; 

ECDSA_SIG*     ECDSA_SIG_new(void);
void           ECDSA_SIG_free(ECDSA_SIG *sig);
ECDSA_SIG*     ECDSA_do_sign(const unsigned char *dgst, int dgst_len, 
                        EC_KEY *eckey);
int            ECDSA_do_verify(const unsigned char *dgst, int dgst_len, 
                        const ECDSA_SIG *sig, EC_KEY* eckey);
ECDSA_SIG*     ECDSA_do_sign_ex(const unsigned char *dgst, int dgstlen, 
                        const BIGNUM *kinv, const BIGNUM *rp,
                        EC_KEY *eckey);
int            ECDSA_sign_setup(EC_KEY *eckey, BN_CTX *ctx,
                        BIGNUM **kinv, BIGNUM **rp);
void ECDSA_SIG_get0(BIGNUM **pr, BIGNUM **ps, ECDSA_SIG *sig);

int i2d_ECDSA_SIG(const ECDSA_SIG *sig, unsigned char **pp);
ECDSA_SIG *d2i_ECDSA_SIG(ECDSA_SIG **sig, const unsigned char **pp, long len);
int ECDSA_size(const EC_KEY *eckey);


// The ECKEY interface

EC_KEY *EC_KEY_new(void);
void EC_KEY_free(EC_KEY *key);

int EC_KEY_set_group(EC_KEY *key, const EC_GROUP *group);
int EC_KEY_set_private_key(EC_KEY *key, const BIGNUM *prv);
int EC_KEY_set_public_key(EC_KEY *key, const EC_POINT *pub);
int EC_KEY_precompute_mult(EC_KEY *key, BN_CTX *ctx);

// BP Functions

typedef ... BP_GROUP;
typedef ... G1_ELEM;
typedef ... G2_ELEM;
typedef ... GT_ELEM;


#define NID_fp254bnb          1

BP_GROUP *BP_GROUP_new(void);
BP_GROUP *BP_GROUP_new_by_curve_name(int nid);
void BP_GROUP_clear_free(BP_GROUP *group);
BP_GROUP *BP_GROUP_dup(const BP_GROUP *a);
 const EC_GROUP *BP_GROUP_get_group_G1(BP_GROUP *group);
int BP_GROUP_get_order(const BP_GROUP *group, BIGNUM *order, BN_CTX *ctx);

int BP_GROUP_get_generator_G1(const BP_GROUP *group, G1_ELEM *g);
int BP_GROUP_precompute_mult_G1(BP_GROUP *group, BN_CTX *ctx);
int BP_GROUP_get_generator_G2(const BP_GROUP *group, G2_ELEM *g);
int BP_GROUP_precompute_mult_G2(BP_GROUP *group, BN_CTX *ctx);


G1_ELEM *G1_ELEM_new(const BP_GROUP *group);
void G1_ELEM_free(G1_ELEM *point);
void G1_ELEM_clear_free(G1_ELEM *point);
int G1_ELEM_copy(G1_ELEM *dst, const G1_ELEM *src);
G1_ELEM *G1_ELEM_dup(const G1_ELEM *src, const BP_GROUP *group);
int G1_ELEM_set_to_infinity(const BP_GROUP *group, G1_ELEM *point);
int G1_ELEM_set_Jprojective_coordinates(const BP_GROUP *group,
                                        G1_ELEM *point, const BIGNUM *x,
                                        const BIGNUM *y,
                                        const BIGNUM *z, BN_CTX *ctx);
int G1_ELEM_get_Jprojective_coordinates(const BP_GROUP *group,
                                        const G1_ELEM *point, BIGNUM *x,
                                        BIGNUM *y, BIGNUM *z,
                                        BN_CTX *ctx);
int G1_ELEM_set_affine_coordinates(const BP_GROUP *group, G1_ELEM *point,
                                   const BIGNUM *x, const BIGNUM *y,
                                   BN_CTX *ctx);
int G1_ELEM_get_affine_coordinates(const BP_GROUP *group,
                                   const G1_ELEM *point, BIGNUM *x,
                                   BIGNUM *y, BN_CTX *ctx);
int G1_ELEM_set_compressed_coordinates(const BP_GROUP *group,
                                       G1_ELEM *point, const BIGNUM *x,
                                       int y_bit, BN_CTX *ctx);
size_t G1_ELEM_point2oct(const BP_GROUP *group, const G1_ELEM *point,
                         point_conversion_form_t form, unsigned char *buf,
                         size_t len, BN_CTX *ctx);
int G1_ELEM_oct2point(const BP_GROUP *group, const G1_ELEM *point,
                      const unsigned char *buf, size_t len, BN_CTX *ctx);

/********************************************************************/
/*              Functions for arithmetic in group G1                */
/********************************************************************/

int G1_ELEM_add(const BP_GROUP *group, G1_ELEM *r, const G1_ELEM *a,
                const G1_ELEM *b, BN_CTX *ctx);
int G1_ELEM_dbl(const BP_GROUP *group, G1_ELEM *r, const G1_ELEM *a,
                BN_CTX *ctx);
int G1_ELEM_invert(const BP_GROUP *group, G1_ELEM *a, BN_CTX *ctx);
int G1_ELEM_is_at_infinity(const BP_GROUP *group, const G1_ELEM *point);
int G1_ELEM_is_on_curve(const BP_GROUP *group, const G1_ELEM *point,
                        BN_CTX *ctx);
int G1_ELEM_cmp(const BP_GROUP *group, const G1_ELEM *point,
                const G1_ELEM *b, BN_CTX *ctx);
int G1_ELEM_make_affine(const BP_GROUP *group, G1_ELEM *point, BN_CTX *ctx);
int G1_ELEMs_make_affine(const BP_GROUP *group, size_t num,
                         G1_ELEM *points[], BN_CTX *ctx);
int G1_ELEM_mul(const BP_GROUP *group, G1_ELEM *r, const BIGNUM *g_scalar,
                const G1_ELEM *point, const BIGNUM *p_scalar,
                BN_CTX *ctx);

int G1_ELEMs_mul(const BP_GROUP *group, G1_ELEM *r, const BIGNUM *scalar,
                 size_t num, const G1_ELEM *points[],
                 const BIGNUM *scalars[], BN_CTX *ctx);

/********************************************************************/
/*              Functions for managing G2 elements                  */
/********************************************************************/

G2_ELEM *G2_ELEM_new(const BP_GROUP *group);
void G2_ELEM_free(G2_ELEM *point);
void G2_ELEM_clear_free(G2_ELEM *point);
int G2_ELEM_copy(G2_ELEM *dst, const G2_ELEM *src);
G2_ELEM *G2_ELEM_dup(const G2_ELEM *src, const BP_GROUP *group);

/********************************************************************/
/*              Functions for arithmetic in group G2                */
/********************************************************************/

int G2_ELEM_set_to_infinity(const BP_GROUP *group, G2_ELEM *point);
int G2_ELEM_set_Jprojective_coordinates(const BP_GROUP *group,
                                        G2_ELEM *point, const BIGNUM *x[2],
                                        const BIGNUM *y[2],
                                        const BIGNUM *z[2], BN_CTX *ctx);
int G2_ELEM_get_Jprojective_coordinates(const BP_GROUP *group,
                                        const G2_ELEM *point, BIGNUM *x[2],
                                        BIGNUM *y[2], BIGNUM *z[2],
                                        BN_CTX *ctx);
int G2_ELEM_set_affine_coordinates(const BP_GROUP *group, G2_ELEM *point,
                                   const BIGNUM *x[2], const BIGNUM *y[2],
                                   BN_CTX *ctx);
int G2_ELEM_get_affine_coordinates(const BP_GROUP *group,
                                   const G2_ELEM *point, BIGNUM *x[2], BIGNUM *y[2],
                                   BN_CTX *ctx);
size_t G2_ELEM_point2oct(const BP_GROUP *group, const G2_ELEM *point,
                         point_conversion_form_t form, unsigned char *buf,
                         size_t len, BN_CTX *ctx);
int G2_ELEM_oct2point(const BP_GROUP *group, G2_ELEM *point,
                      const unsigned char *buf, size_t len, BN_CTX *ctx);

/********************************************************************/
/*              Functions for arithmetic in group G2                */
/********************************************************************/

int G2_ELEM_add(const BP_GROUP *group, G2_ELEM *r, const G2_ELEM *a,
                const G2_ELEM *b, BN_CTX *ctx);
int G2_ELEM_dbl(const BP_GROUP *group, G2_ELEM *r, const G2_ELEM *a,
                BN_CTX *ctx);
int G2_ELEM_invert(const BP_GROUP *group, G2_ELEM *point, BN_CTX *ctx);
int G2_ELEM_is_at_infinity(const BP_GROUP *group, const G2_ELEM *point);
int G2_ELEM_is_on_curve(const BP_GROUP *group, const G2_ELEM *point,
                        BN_CTX *ctx);
int G2_ELEM_cmp(const BP_GROUP *group, const G2_ELEM *point,
                const G2_ELEM *b, BN_CTX *ctx);
int G2_ELEM_make_affine(const BP_GROUP *group, G2_ELEM *point, BN_CTX *ctx);
int G2_ELEMs_make_affine(const BP_GROUP *group, size_t num,
                         G2_ELEM *points[], BN_CTX *ctx);
int G2_ELEM_mul(const BP_GROUP *group, G2_ELEM *r, const BIGNUM *g_scalar,
                const G2_ELEM *point, const BIGNUM *p_scalar,
                BN_CTX *ctx);
int G2_ELEMs_mul(const BP_GROUP *group, G2_ELEM *r, const BIGNUM *scalar,
                 size_t num, const G2_ELEM *points[],
                 const BIGNUM *scalars[], BN_CTX *ctx);

/********************************************************************/
/*              Functions for managing GT elements                  */
/********************************************************************/

GT_ELEM *GT_ELEM_new(const BP_GROUP *group);
void GT_ELEM_free(GT_ELEM *elem);
void GT_clear_free(GT_ELEM *a);
int GT_ELEM_copy(GT_ELEM *dst, const GT_ELEM *src);
GT_ELEM *GT_ELEM_dup(const GT_ELEM *src, const BP_GROUP *group);
int GT_ELEM_zero(GT_ELEM *a);
int GT_ELEM_is_zero(GT_ELEM *a);
int GT_ELEM_set_to_unity(const BP_GROUP *group, GT_ELEM *a);
int GT_ELEM_is_unity(const BP_GROUP *group, const GT_ELEM *a);
size_t GT_ELEM_elem2oct(const BP_GROUP *group, const GT_ELEM *a,
                         unsigned char *buf, size_t len, BN_CTX *ctx);
int GT_ELEM_oct2elem(const BP_GROUP *group, GT_ELEM *a,
                      const unsigned char *buf, size_t len, BN_CTX *ctx);
int GT_ELEM_add(const BP_GROUP *group, GT_ELEM *r, const GT_ELEM *a,
                const GT_ELEM *b, BN_CTX *ctx);
int GT_ELEM_sub(const BP_GROUP *group, GT_ELEM *r, const GT_ELEM *a,
                const GT_ELEM *b, BN_CTX *ctx);
int GT_ELEM_sqr(const BP_GROUP *group, GT_ELEM *r, const GT_ELEM *a,
                BN_CTX *ctx);
int GT_ELEM_mul(const BP_GROUP *group, GT_ELEM *r, GT_ELEM *a, GT_ELEM *b, BN_CTX *ctx);
int GT_ELEM_inv(const BP_GROUP *group, GT_ELEM *r, GT_ELEM *a, BN_CTX *ctx);
int GT_ELEM_cmp(const GT_ELEM *a, const GT_ELEM *b);
int GT_ELEM_exp(const BP_GROUP *group, GT_ELEM *r, const GT_ELEM *a, const BIGNUM *b,
                BN_CTX *ctx);
int GT_ELEM_pairing(const BP_GROUP *group, GT_ELEM *r, const G1_ELEM *p,
                    const G2_ELEM *q, BN_CTX *ctx);
int GT_ELEMs_pairing(const BP_GROUP *group, GT_ELEM *r, size_t num,
                     const G1_ELEM *p[], const G2_ELEM *q[], BN_CTX *ctx);



""")

#def cffi_compile():
print("Compiling petlib ...")
_FFI.compile(verbose=True)