/* example.i */
 %module Sodium
%include "typemaps.i"
%include "stdint.i"
%include "arrays_java.i"
%include "carrays.i"
%include "various.i"

%apply int {unsigned long long};
%apply long[] {unsigned long long *};


%typemap(jni) unsigned char *"jbyteArray"
%typemap(jtype) unsigned char *"byte[]"
%typemap(jstype) unsigned char *"byte[]"
%typemap(in) unsigned char *{
    $1 = (unsigned char *) JCALL2(GetByteArrayElements, jenv, $input, 0);
}

%typemap(argout) unsigned char *{
    JCALL3(ReleaseByteArrayElements, jenv, $input, (jbyte *) $1, 0);
}

%typemap(javain) unsigned char *"$javainput"

/* Prevent default freearg typemap from being used */
%typemap(freearg) unsigned char *""



/* char types */
%typemap(jni) char *BYTE "jbyteArray"
%typemap(jtype) char *BYTE "byte[]"
%typemap(jstype) char *BYTE "byte[]"
%typemap(in) char *BYTE {
    $1 = (char *) JCALL2(GetByteArrayElements, jenv, $input, 0);
}

%typemap(argout) char *BYTE {
    JCALL3(ReleaseByteArrayElements, jenv, $input, (jbyte *) $1, 0);
}

%typemap(javain) char *BYTE "$javainput"

/* Prevent default freearg typemap from being used */
%typemap(freearg) char *BYTE ""







/* ***************************** */


/*
%typemap(jni) unsigned char*        "jbyteArray"
%typemap(jtype) unsigned char*      "byte[]"
%typemap(jstype) unsigned char*     "byte[]"
*/
 
%{
 /* Put header files here or function declarations like below */
#include "sodium.h"

 %}
/** \mainpage
 *
 * __NaCl__ (pronounced _salt_) is a new easy-to-use high-speed
 * software library for network communication, encryption, decryption,
 * signatures, etc. NaCl's goal is to provide all of the core
 * operations needed to build higher-level cryptographic tools.
 *
 * __Sodium__ is a portable, cross-compilable, installable,
 * packageable, API-compatible version of NaCl.
 *
 * Unfortunately, the documentation for the ABI is not
 * _well-documented_. To this end this file contains a
 * _well-documented_ copy of the C high-level abstract crypto ABI
 * provided by the NaCl and Sodium projects. The ABI has been
 * documented using the Doxygen documentation tool.
 *
 * The text for the documentation has been adapted from the existing
 * ABI documention for NaCl, and Sodium that can be found on the
 * project's respective websites. This header file is for
 * documentation purposes _only_ and should not be used within coding
 * projects.
 *
 * More information concerning NaCl and sodium can be found online:
 * 
 *  - <http://nacl.cr.yp.to/>
 *  - <https://github.com/jedisct1/libsodium>
 *
 * @note The values shown for various definitions are implementation
 * specific and are there for illustrative purposes only.
 *
 * @author Jan de Muijnck-Hughes <jfdm at st-andrews dot ac dot uk>
 * @copyright 
 *
 * - NaCl software and API are public domain artefacts.
 * - Sodium and API is Copyright (c) 2013 Frank Denis `<j at pureftpd dot org>`
 *
 * @date 2013-03-27
 *
 * @todo add math definitions
 * @todo add proper documentation for the precomputation interface for stream encryption.
 * @todo add documentation for the security model.
 * @todo add documentation for crypto models.
 * @todo make header file agnostic for instant inclusion upstream.
 *
 */
// ------------------------------------------------- [ Public Key Cryptography ]

// ------------------------------------- [ Authenticated Public-Key Encryption ]
/**
 * \defgroup apke Authenticated Public-Key Encryption
 *
 * Definitions and functions to perform Authenticated Encryption. 
 *
 * Authentication encryption provides guarantees towards the:
 *
 * - confidentiality
 * - integrity
 * - authenticity
 *
 * of data.
 *
 * Alongside the standard interface there also exists a
 * pre-computation interface. In the event that applications are
 * required to send several messages to the same receiver, speed can
 * be gained by splitting the operation into two steps: before and
 * after. Similarly applications that receive several messages from
 * the same sender can gain speed through the use of the: before, and
 * open_after functions.
 *
 * @{
 */
#define crypto_box_PUBLICKEYBYTES 32 ///< Size of Public Key. 
#define crypto_box_SECRETKEYBYTES 32 ///< Size of Secret Key. 
#define crypto_box_BEFORENMBYTES  32 ///< Size of pre-computed ciphertext. 
#define crypto_box_NONCEBYTES     24 ///< Size of Nonce. 
#define crypto_box_ZEROBYTES      32 ///< No. of leading 0 bytes in the message. 
#define crypto_box_BOXZEROBYTES   16 ///< No. of leading 0 bytes in the cipher-text. 

/**
 * Randomly generates a secret key and a corresponding public key. 
 *
 * @param[out] pk the buffer for the public key
 * @param[out] sk the buffer for the private key with length crypto_box_SECRETKEYTBYTES
 *
 * @return 0 if generation successful.
 *
 * @pre the buffer for pk must be at least crypto_box_PUBLICKEYBYTES in length
 * @pre the buffer for sk must be at least crypto_box_SECRETKEYTBYTES in length
 * @post first crypto_box_PUBLICKEYTBYTES of pk will be the key data.
 * @post first crypto_box_SECRETKEYTBYTES of sk will be the key data.
 *
 * Example innvocation:
 *
 *~~~~~{.c}
 *
 * unsigned char pk[crypto_box_PUBLICKEYBYTES];
 * unsigned char sk[crypto_box_SECRETKEYBYTES];
 *
 * crypto_box_keypair(pk,sk);
 *~~~~~
 *
 */
int crypto_box_keypair(unsigned char * pk, unsigned char * sk);

/**
 * Encrypts a message given the senders secret key, and receivers
 * public key.
 *
 * @param[out] ctxt   the buffer for the cipher-text.
 * @param[in]  msg    the message to be encrypted.
 * @param[in]  mlen   the length of msg.
 * @param[in]  nonce  a randomly generated nonce.
 * @param[in]  pk     the receivers public key, used for encryption.
 * @param[in]  sk     the senders private key, used for signing.
 *
 * @return 0 if operation is successful.
 *
 * @pre  first crypto_box_ZEROBYTES of msg be all 0.
 * @pre  the nonce must have size crypto_box_NONCEBYTES.
 * @post first crypto_box_BOXZERBYTES of ctxt be all 0.
 * @post first mlen bytes of ctxt will contain the ciphertext.
 *
 * Example innvocation:
 *
 *~~~~~{.c}
 * const unsigned char pk[crypto_box_PUBLICKEYBYTES];
 * const unsigned char sk[crypto_box_SECRETKEYBYTES];
 * const unsigned char n[crypto_box_NONCEBYTES];
 * const unsigned char m[...];
 * unsigned long long mlen;
 * unsigned char c[...];
 *
 * crypto_box(c,m,mlen,n,pk,sk);
 *~~~~~
 */
int crypto_box(unsigned char*       ctxt,
               const unsigned char* msg,
               unsigned long long   mlen,
               const unsigned char* nonce,
               const unsigned char* pk,
               const unsigned char* sk);

/**
 * Decrypts a ciphertext ctxt given the receivers private key, and
 * senders public key.
 *
 * @param[out] msg    the buffer to place resulting plaintext.
 * @param[in]  ctxt   the ciphertext to be decrypted.
 * @param[in]  clen   the length of the ciphertext.
 * @param[in]  nonce  a randomly generated.
 * @param[in]  pk     the senders public key, used for verification.
 * @param[in]  sk     the receivers private key, used for decryption.
 *
 * @return 0 if successful and -1 if verification fails.
 *
 * @pre  first crypto_box_BOXZEROBYTES of ctxt be all 0.
 * @pre  the nonce must have size crypto_box_NONCEBYTES.
 * @post first clen bytes of msg will contain the plaintext.
 * @post first crypto_box_ZEROBYTES of msg will be all 0.
 *
 * Example innvocation:
 *
 *~~~~~{.c}
 * const unsigned char pk[crypto_box_PUBLICKEYBYTES];
 * const unsigned char sk[crypto_box_SECRETKEYBYTES];
 * const unsigned char n[crypto_box_NONCEBYTES];
 * const unsigned char c[...]; unsigned long long clen;
 * unsigned char m[...];
 *
 * crypto_box_open(m,c,clen,n,pk,sk);
 *~~~~~
 */
int crypto_box_open(unsigned char*       msg,
                    const unsigned char* ctxt,
                    unsigned long long   clen,
                    const unsigned char* nonce,
                    const unsigned char* pk,
                    const unsigned char* sk);
/**
 * Partially performs the computation required for both encryption and
 * decryption of data.
 * 
 * @param[out] k  the result of the computation.
 * @param[in]  pk the receivers public key, used for encryption.
 * @param[in]  sk the senders private key, used for signing.
 *
 * The intermediate data computed by crypto_box_beforenm is suitable
 * for both crypto_box_afternm and crypto_box_open_afternm, and can be
 * reused for any number of messages.
 *
 * Example innvocation:
 *
 *~~~~~{.c}  
 * unsigned char k[crypto_box_BEFORENMBYTES];
 * const unsigned char pk[crypto_box_PUBLICKEYBYTES];
 * const unsigned char sk[crypto_box_SECRETKEYBYTES];
 *  
 * crypto_box_beforenm(k,pk,sk);
 *~~~~~
 */
int crypto_box_beforenm(unsigned char*       k,
                        const unsigned char* pk,
                        const unsigned char* sk);
/**
 * Encrypts a given a message m, using partial computed data.
 * 
 * @param[out] ctxt   the buffer for the cipher-text.
 * @param[in]  msg    the message to be encrypted.
 * @param[in]  mlen   the length of msg.
 * @param[in]  nonce  a randomly generated nonce.
 * @param[in]  k      the partial computed data.
 *
 * @return 0 if operation is successful.
 *
 * @pre  first crypto_box_ZEROBYTES of msg be all 0.
 * @pre  the nonce must have size crypto_box_NONCEBYTES.
 * @post first crypto_box_BOXZERBYTES of ctxt be all 0.
 * @post first mlen bytes of ctxt will contain the ciphertext.
 *
 * Example innvocation:
 *
 *~~~~~{.c}
 * const unsigned char k[crypto_box_BEFORENMBYTES];
 * const unsigned char n[crypto_box_NONCEBYTES];
 * const unsigned char m[...]; unsigned long long mlen;
 * unsigned char c[...];
 *  
 * crypto_box_afternm(c,m,mlen,n,k);
 *~~~~~
 */
int crypto_box_afternm(unsigned char*       ctxt,
                       const unsigned char* msg,
                       unsigned long long   mlen,
                       const unsigned char* nonce,
                       const unsigned char* k);

/**
 * Decrypts a ciphertext ctxt given the receivers private key, and
 * senders public key.
 *
 * @param[out] msg    the buffer to place resulting plaintext.
 * @param[in]  ctxt   the ciphertext to be decrypted.
 * @param[in]  clen   the length of the ciphertext.
 * @param[in]  nonce  a randomly generated nonce.
 * @param[in]  k      the partial computed data.
 *
 * @return 0 if successful and -1 if verification fails.
 *
 * @pre  first crypto_box_BOXZEROBYTES of ctxt be all 0.
 * @pre  the nonce must have size crypto_box_NONCEBYTES.
 * @post first clen bytes of msg will contain the plaintext.
 * @post first crypto_box_ZEROBYTES of msg will be all 0.
 *
 * Example innvocation:
 *
 *~~~~~{.c}
 * 
 * const unsigned char k[crypto_box_BEFORENMBYTES];
 * const unsigned char n[crypto_box_NONCEBYTES];
 * const unsigned char c[...]; unsigned long long clen;
 * unsigned char m[...];
 *  
 * crypto_box_open_afternm(m,c,clen,n,k);
 *~~~~~
 */

int crypto_box_open_afternm(unsigned char*       msg,
                            const unsigned char* ctxt,
                            unsigned long long   clen,
                            const unsigned char* nonce,
                            const unsigned char* k);
/** @} */

// -------------------------------------------------------------- [ Signatures ]
/** \defgroup dsig Digital Signatures
 *
 * Definitions and functions to perform digital signatures.
 *
 * @{
 */

#define crypto_sign_BYTES          64 ///< length of resulting signature.
#define crypto_sign_PUBLICKEYBYTES 32 ///< length of verification key.
#define crypto_sign_SECRETKEYBYTES 64 ///< length of signing key.

/**
 * Generates a signing/verification key pair.
 *
 * @param[out] vk the verification key.
 * @param[out] sk the signing key.
 *
 * @return 0 if operation successful.
 *
 * @pre the buffer for vk must be at least crypto_sign_PUBLICKEYBYTES in length
 * @pre the buffer for sk must be at least crypto_sign_SECRETKEYTBYTES in length
 * @post first crypto_sign_PUBLICKEYTBYTES of vk will be the key data.
 * @post first crypto_sign_SECRETKEYTBYTES of sk will be the key data.
 *
 *
 *~~~~~{.c}
 * unsigned char vk[crypto_sign_PUBLICKEYBYTES];
 * unsigned char sk[crypto_sign_SECRETKEYBYTES];
 *
 * crypto_sign_keypair(vk,sk);
 *~~~~~
 */
int crypto_sign_keypair(unsigned char *vk, unsigned char* sk);

/**
 * Signs a given message using the signer's signing key.
 *
 * @param[out] sig   the resulting signature.
 * @param[out] slen  the length of the signature.
 * @param[in]  msg   the message to be signed.
 * @param[in]  mlen  the length of the message.
 * @param[in]  sk    the signing key.
 *
 * @return 0 if operation successful
 *
 * @pre sig must be of length mlen+crypto_sign_BYTES
 *
 *~~~~~{.c}
 * const unsigned char sk[crypto_sign_SECRETKEYBYTES];
 * const unsigned char m[...];
 * unsigned long long mlen;
 * unsigned char sm[...];
 * unsigned long long smlen;
 * 
 * crypto_sign(sm,&smlen,m,mlen,sk);
 *~~~~~
 */
int crypto_sign(unsigned char*       sig,
                unsigned long long*  slen,
                const unsigned char* msg,
                unsigned long long   mlen,
                const unsigned char* sk);

/**
 * Verifies the signed message sig using the signer's verification key.
 *
 * @param[out] msg the resulting message.
 * @param[out] mlen the length of msg.
 * @param[in]  sig the signed message.
 * @param[in]  smlen length of the signed message.
 * @param[in]  vk the verification key.
 *
 * @return 0 if successful, -1 if verification fails.
 *
 * @pre length of msg must be at least smlen
 *
 * @warning if verification fails msg may contain data from the
 * computation.
 *
 * Example innvocation:
 *
 *~~~~~{.c}
 * const unsigned char pk[crypto_sign_PUBLICKEYBYTES];
 * const unsigned char sm[...]; unsigned long long smlen;
 * unsigned char m[...]; unsigned long long mlen;
 * 
 * crypto_sign_open(m,&mlen,sm,smlen,pk);
 *~~~~~
 */
int crypto_sign_open(unsigned char*       msg,
                     unsigned long long*  mlen,
                     const unsigned char* sig,
                     unsigned long long   smlen,
                     const unsigned char* vk);

/** @} */

// --------------------------------------- [ Secret-Key Cryptography Functions ]
// ------------------------------------------------ [ Authenticated Encryption ]
/**
 * \defgroup asymenc Authenticated Symmetric Encryption
 *
 * Definitions and functions for authenticated symmetric encryption.
 *
 * @{
 */

#define crypto_secretbox_KEYBYTES     32 ///< Size of symmetric key.
#define crypto_secretbox_NONCEBYTES   24 ///< Size of the nonce.
#define crypto_secretbox_ZEROBYTES    32 ///< No. of leading 0 bytes in the message.  
#define crypto_secretbox_BOXZEROBYTES 16 ///< No. of leading 0 bytes in the cipher-text. 

/**
 *
 * Encrypts and authenticates a message using the given secret key, and nonce..
 *
 * @param[out] ctxt   the buffer for the cipher-text.
 * @param[in]  msg    the message to be encrypted.
 * @param[in]  mlen   the length of msg.
 * @param[in]  nonce  a nonce with length crypto_box_NONCEBYTES.
 * @param[in]  key    the shared secret key.
 *
 * @return 0 if operation is successful.
 *
 * @pre  first crypto_secretbox_ZEROBYTES of msg be all 0..
 * @post first crypto_secretbox_BOXZERBYTES of ctxt be all 0.
 * @post first mlen bytes of ctxt will contain the ciphertext.
 *
 *
 *~~~~~{.c}
 * const unsigned char k[crypto_secretbox_KEYBYTES];
 * const unsigned char n[crypto_secretbox_NONCEBYTES];
 * const unsigned char m[...]; unsigned long long mlen;
 * unsigned char c[...]; unsigned long long clen;
 *
 * crypto_secretbox(c,m,mlen,n,k);
 *~~~~~
 */
int crypto_secretbox(unsigned char*       ctxt,
                     const unsigned char* msg,
                     unsigned long long   mlen,
                     const unsigned char* nonce,
                     const unsigned char* key);
/**
 *
 * Decrypts a ciphertext ctxt given the receivers private key, and
 * senders public key.
 *
 * @param[out] msg    the buffer to place resulting plaintext.
 * @param[in]  ctxt   the ciphertext to be decrypted.
 * @param[in]  clen   the length of the ciphertext.
 * @param[in]  nonce  a randomly generated nonce.
 * @param[in]  key    the shared secret key.
 *
 * @return 0 if successful and -1 if verification fails.
 *
 * @pre  first crypto_secretbox_BOXZEROBYTES of ctxt be all 0.
 * @pre  the nonce must be of length crypto_secretbox_NONCEBYTES
 * @post first clen bytes of msg will contain the plaintext.
 * @post first crypto_secretbox_ZEROBYTES of msg will be all 0.
 *
 * @warning if verification fails msg may contain data from the
 * computation.

 * Example innvocation:
 *
 *~~~~~{.c}
 * const unsigned char k[crypto_secretbox_KEYBYTES];
 * const unsigned char n[crypto_secretbox_NONCEBYTES];
 * const unsigned char c[...]; unsigned long long clen;
 * unsigned char m[...];
 *
 * crypto_secretbox_open(m,c,clen,n,k);
 *~~~~~
 */
int crypto_secretbox_open(unsigned char*       msg,
                          const unsigned char* ctxt,
                          unsigned long long   clen,
                          const unsigned char* nonce,
                          const unsigned char* key);

/** < @} */

// -------------------------------------------------------------- [ Encryption ]

/** 
 * \defgroup symenc Symmetric Encryption
 *
 * Definitions and functions for symmetric encryption.
 * 
 * Alongside the standard interface there also exists a
 * pre-computation interface. In the event that applications are
 * required to send several messages to the same receiver, speed can
 * be gained by splitting the operation into two steps: before and
 * after. Similarly applications that receive several messages from
 * the same sender can gain speed through the use of the: before, and
 * open_after functions.
 *
 * @{
 */

#define crypto_stream_KEYBYTES   32 ///< Size of keys used.
#define crypto_stream_NONCEBYTES 24 ///< Size of nonces used.

/**
 * Generates a stream using the given secret key and nonce.
 * 
 * @param[out] stream the generated stream.
 * @param[out] slen   the length of the generated stream.
 * @param[in]  nonce  the nonce used to generate the stream.
 * @param[in]  key    the key used to generate the stream.
 *
 * @return 0 if operation successful
 *
 * @pre  nonce must have minimum length crypto_stream_NONCEBYTES
 * @pre  key must have minimum length crypto_stream_KEYBYTES
 * @post stream will have length slen
 *
 * Example invocation:
 *
 *~~~~~{.c}
 * const unsigned char k[crypto_stream_KEYBYTES];
 * const unsigned char n[crypto_stream_NONCEBYTES];
 * unsigned char c[...]; unsigned long long clen;
 *
 * crypto_stream(c,clen,n,k);
 *~~~~~
 */

int crypto_stream(unsigned char*       stream,
                  unsigned long long   slen,
                  const unsigned char* nonce,
                  const unsigned char* key);

/**
 * Encrypts the given message using the given secret key and nonce.
 * 
 * The crypto_stream_xor function guarantees that the ciphertext is
 * the plaintext (xor) the output of crypto_stream. Consequently
 * crypto_stream_xor can also be used to decrypt.
 *
 * @param[out] ctxt  buffer for the resulting ciphertext.
 * @param[in]  msg   the message to be encrypted.
 * @param[in]  mlen  the length of the message.
 * @param[in]  nonce the nonce used during encryption.
 * @param[in]  key   secret key used during encryption.
 *
 * @return 0 if operation successful.
 *
 * @pre  ctxt must have length minimum mlen.
 * @pre  nonce must have length minimum crypto_stream_NONCEBYTES.
 * @pre  key must have length minimum crpyto_stream_KEYBYTES
 * @post first mlen bytes of ctxt will contain the ciphertext.
 * 
 * Example invocation:
 *
 *~~~~~{.c}
 * const unsigned char k[crypto_stream_KEYBYTES];
 * const unsigned char n[crypto_stream_NONCEBYTES];
 * unsigned char m[...];
 * unsigned long long mlen;
 * unsigned char c[...];
 *
 * crypto_stream_xor(c,m,mlen,n,k);
 *~~~~~
 */
int crypto_stream_xor(unsigned char *c, const unsigned char *m,
                  unsigned long long mlen, const unsigned char *n,
                  const unsigned char *k);

/**
 * @todo document crypto_stream_beforenm
 */
/*
int crypto_stream_beforenm(unsigned char *,
                           const unsigned char *);*/

/**
 * @todo document crypto_stream_afternm
 */
/*
int crypto_stream_afternm(unsigned char *,
                          unsigned long long,
                          const unsigned char *,
                          const unsigned char *);*/

/**
 * @todo document crypto_stream_xor_afternm
 */
/*
int crypto_stream_xor_afternm(unsigned char *,
                              const unsigned char *,
                              unsigned long long,
                              const unsigned char *,
                              const unsigned char *);*/
/** @} */

// ---------------------------------------------------------- [ Authentication ]

/**
 * \defgroup auth Authentication
 *
 * Methods for authentication.
 *
 * @{
 */

#define crypto_auth_BYTES    32 ///< Length of the authenticator
#define crypto_auth_KEYBYTES 32 ///< Length of the key used for authentication.

/**
 * Constructs a one time authentication token for the given message msg using a given secret key.
 *
 * @param[out] tok  the generated authentication token.
 * @param[in]  msg  the message to be authenticated.
 * @param[in]  mlen the length of msg.
 * @param[in]  key  the key used to compute the token.
 *
 * @return 0 if operation successful.
 *
 * @pre  tok must have minimum length crypto_auth_BYTES
 * @pre  key must be of length crypto_auth_KEY_BYTES
 * @post the first crypto_auth_BYTES of auth will contain the result.
 *
 * Example innvocation:
 *
 *~~~~~{.c}
 * const unsigned char k[crypto_auth_KEYBYTES];
 * const unsigned char m[...]; unsigned long long mlen;
 * unsigned char a[crypto_auth_BYTES];
 *
 * crypto_auth(a,m,mlen,k);
 *~~~~~
 */
int crypto_auth(unsigned char*       tok,
                const unsigned char* msg,
                unsigned long long   mlen,
                const unsigned char* key) ;

/**
 * Verifies that the given authentication token is correct for the
 * given message and key.
 *
 * @param[out] tok the generated token.
 * @param[in]  msg  the message to be authenticated.
 * @param[in]  mlen the length of msg.
 * @param[in]  key  the key used to compute the authentication.
 *
 * @return 0 if tok is the correct token for msg under the
 * given key. Otherwise -1.
 *
 * @pre  tok must have minimum length crypto_auth_BYTES
 * @pre  key must be of length crypto_auth_KEY_BYTES
 *
 *~~~~~{.c}
 * const unsigned char k[crypto_auth_KEYBYTES];
 * const unsigned char m[...]; unsigned long long mlen;
 * const unsigned char a[crypto_auth_BYTES];
 *
 * crypto_auth_verify(a,m,mlen,k);
 *~~~~~
 */
int crypto_auth_verify(const unsigned char* tok,
                       const unsigned char* msg,
                       unsigned long long   mlen,
                       const unsigned char* key);

/** @} */

// ------------------------------------------------- [ One-time Authentication ]

/**
 * \defgroup onetimeauth One-Time Authentication
 *
 * Methods for one-time authentication.
 *
 * @{
 */

#define crypto_onetimeauth_BYTES    16 ///< Size of the authentication token.
#define crypto_onetimeauth_KEYBYTES 32 ///< Size of the secret key used.

/**
 * Constructs a one time authentication token for the given message msg using a given secret key.
 *
 * @param[out] tok  the generated token.
 * @param[in]  msg  the message to be authenticated.
 * @param[in]  mlen the length of msg.
 * @param[in]  key  the key used to compute the authentication.
 *
 * @return 0 if operation successful.
 *
 * @pre  token must have minimum length crypto_onetimeauth_BYTES
 * @pre  key must be of length crypto_onetimeauth_KEY_BYTES
 * @post the first crypto_onetimeauth_BYTES of the token will contain the result.
 *
 * Example innvocation:
 *
 *~~~~~{.c}
 * const unsigned char k[crypto_onetimeauth_KEYBYTES];
 * const unsigned char m[...]; unsigned long long mlen;
 * unsigned char a[crypto_onetimeauth_BYTES];

 * crypto_onetimeauth(a,m,mlen,k);
 *~~~~~
 */
int crypto_onetimeauth(unsigned char*       tok,
                       const unsigned char* msg,
                       unsigned long long   mlen,
                       const unsigned char* key);

/**
 * Verifies that the given authentication token is correct for the
 * given message and key.
 *
 * @param[out] tok the generated token.
 * @param[in]  msg  the message to be authenticated.
 * @param[in]  mlen the length of msg.
 * @param[in]  key  the key used to compute the authentication.
 *
 * @return 0 if tok is the correct token for msg under the
 * given key. Otherwise -1.
 *
 * @pre  tok must have minimum length crypto_onetimeauth_BYTES
 * @pre  key must be of length crypto_onetimeauth_KEY_BYTES
 *
 *~~~~~{.c}
 * const unsigned char k[crypto_onetimeauth_KEYBYTES];
 * const unsigned char m[...]; unsigned long long mlen;
 * const unsigned char a[crypto_onetimeauth_BYTES];
 *
 * crypto_onetimeauth_verify(a,m,mlen,k);
 *~~~~~
 */
int crypto_onetimeauth_verify(const unsigned char* tok,
                              const unsigned char* msg,
                              unsigned long long   mlen,
                              const unsigned char* key);

/** @} */

// ------------------------------------------------ [ Low-Level NaCl Functions ]

// ----------------------------------------------------------------- [ Hashing ]
/** 
 * \defgroup hash Methods for Hashing
 *
 * Utility function to allow for hash computation.
 *
 * @{
 */

#define crypto_hash_BYTES 64 ///< Size of the computed hash.

/**
 * Compute a crypto_hash_BYTES hash of the given message.
 *
 * @param[out] hbuf a buffer to store the resulting hash.
 * @param[in]  msg  the message to be hashed.
 * @param[in]  mlen the length of the message to be hashed.
 *
 * @return 0 if successful operation.
 *
 * @pre  hbuf must have length minimum crypto_hash_BYTES.
 * @post first crypto_hash_BYTES. of hbuf will contain the hash.
 *
 * Example Innvocation:
 *
 *~~~~~{.c}
 * const unsigned char m[...]; unsigned long long mlen;
 * unsigned char h[crypto_hash_BYTES];
 *
 * crypto_hash(h,m,mlen);
 *~~~~~
 */

int crypto_hash(unsigned char*       hbuf,
                const unsigned char* msg,
                unsigned long long   mlen);

/** @} */

// ------------------------------------------------------- [ String Comparison ]

/**
 * \defgroup strcmp String Comparison
 *
 * Methods to compare 16 and 32 byte strings.
 *
 * @{
 */

#define crypto_verify_16_BYTES 16
#define crypto_verfiy_32_BYTES 32

/**
 * Compares the first crypto_verify_16_BYTES of the given strings.
 *
 * @param[in] string1 a string
 * @param[in] string2 another string
 *
 * @return 0 if string1 and string2 are equal, otherwise -1.
 *
 * @pre string1 must be minimum of crypto_verify_16_BYTES long.
 * @pre string2 must be minimum of crypto_verify_16_BYTES long.
 *
 * @note The time taken by the function is independent of the contents
 * of string1 and string2. In contrast, the standard C comparison
 * function memcmp(string1,string2,16) takes time that is dependent on
 * the longest matching prefix of string1 and string2. This often
 * allows for easy timing attacks.
 *
 * Example invocation:
 *
 *~~~~~{.c}
 * const unsigned char x[16];
 * const unsigned char y[16];
 *
 * crypto_verify_16(x,y);
 *~~~~~
 */
int crypto_verify_16(const unsigned char* string1, const unsigned char* string2);

/**
 * Compares the first crypto_verify_32_BYTES of the given strings.
 *
 * @param[in] string1 a string
 * @param[in] string2 another string
 *
 * @return 0 if string1 and string2 are equal, otherwise -1.
 *
 * @pre string1 must be minimum of crypto_verify_32_BYTES long.
 * @pre string2 must be minimum of crypto_verify_32_BYTES long.
 *
 * @note The time taken by the function is independent of the contents
 * of string1 and string2. In contrast, the standard C comparison
 * function memcmp(string1,string2,32) takes time that is dependent on
 * the longest matching prefix of string1 and string2. This often
 * allows for easy timing attacks.
 *
 * Example invocation:
 *
 *~~~~~{.c}
 * const unsigned char x[32];
 * const unsigned char y[32];
 *
 * crypto_verify_32(x,y);
 *~~~~~
 */
int crypto_verify_32(const unsigned char* string1, const unsigned char* string2);

/** @} */

// ------------------------------------------------------ [ libsodium Specific ]

// ---------------------------------------------------- [ Randombyte Generator ]
/**
 * \defgroup randbytes Random byte generation
 *
 * Utility functions provided by libSodium. The documentation here is
 * taken directly from the libSodium website.
 *
 *
 * @todo add details for custom randombyte implementations.
 * @todo add proper documentation to denote parameters, and descriptions
 *
 * @{
 */

/**
 * Fill the specified buffer with size random bytes.
 */
void randombytes(unsigned char *buf, unsigned long long size);

/**
 * Return a random 32-bit unsigned value.
 */
uint32_t randombytes_random(void);

/**
 * Generate a new key for the pseudorandom number generator. The file
 * descriptor for the entropy source is kept open, so that the
 * generator can be reseeded even in a chroot() jail.
 *
 */
void randombytes_stir(void);

/**
 * Return a value between 0 and upper_bound using a uniform
 * distribution.
 */
uint32_t randombytes_uniform(const uint32_t upper_bound);

/**
 * Fill the specified buffer with size random bytes.
 */
void randombytes_buf(void* const buf, const size_t size);

/**
 * Close the file descriptor or the handle for the cryptographic
 * service provider.
 */
int randombytes_close(void);

/** @} */

// ------------------------------------------------------- [ Utility Functions ]

/**
 * \defgroup util Utility functions
 *
 * A set of utility functions from libsodium to return version
 * numbering and securely wiping memory.
 *
 * @{
 */

const char *sodium_version_string(void); ///< Return the version string.
int         sodium_library_version_major(void);  ///< Return the major version number.
int         sodium_library_version_minor(void);  ///< Return the minor version number.

/**
 * Securely wipe a region in memory.
 *
 * @param[in] pnt  the region on memory
 * @param[in] size the size of the region to be wiped.
 *
 * @warning If a region has been allocated on the heap, you still have
 * to make sure that it can't get swapped to disk, possibly using
 * mlock(2).
 *
 */
void sodium_memzero(void * const pnt, const size_t size);

/** @} */

// --------------------------------------------------------------------- [ EOF ]
