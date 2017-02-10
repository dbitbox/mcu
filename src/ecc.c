/*

 The MIT License (MIT)

 Copyright (c) 2015-2016 Douglas J. Bakkum

 Permission is hereby granted, free of charge, to any person obtaining
 a copy of this software and associated documentation files (the "Software"),
 to deal in the Software without restriction, including without limitation
 the rights to use, copy, modify, merge, publish, distribute, sublicense,
 and/or sell copies of the Software, and to permit persons to whom the
 Software is furnished to do so, subject to the following conditions:

 The above copyright notice and this permission notice shall be included
 in all copies or substantial portions of the Software.

 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES
 OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 OTHER DEALINGS IN THE SOFTWARE.

*/


// TODO - add normalization for uECC curves (low S)


#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "sha2.h"
#include "flags.h"
#include "utils.h"
#include "random.h"
#include "ecc.h"
#include "secp256k1/include/secp256k1.h"
#include "secp256k1/include/secp256k1_ecdh.h"
#include "uECC.h"


static secp256k1_context *ctx = NULL;


static int ecc_uECC_rng_function(uint8_t *r, unsigned l)
{
    int ret = random_bytes(r, l, 0);
    if (ret == DBB_OK) {
        return 1;
    }
    return 0;
}


void ecc_context_init(void)
{
#ifndef ECC_USE_UECC_LIB // reduce binary size by not setting ctx if not used
#ifdef TESTING
    ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
#else
    ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
#endif
    uint8_t rndm[32] = {0};
    random_bytes(rndm, sizeof(rndm), 0);
    if (secp256k1_context_randomize(ctx, rndm)) {
        /* pass */
    }
#endif
    uECC_RNG_Function rng_function = ecc_uECC_rng_function;
    uECC_set_rng(rng_function);
}


void ecc_context_destroy(void)
{
#ifndef ECC_USE_UECC_LIB
    secp256k1_context_destroy(ctx);
#endif
}


int ecc_sign_digest(const ecc_curve_id curve, const uint8_t *private_key,
                    const uint8_t *data, uint8_t *sig)
{
    if (curve == ECC_CURVE_libsecp256k1) {
        secp256k1_ecdsa_signature signature;

        if (!ctx) {
            ecc_context_init();
        }

        if (secp256k1_ecdsa_sign(ctx, &signature, (const unsigned char *)data,
                                 (const unsigned char *)private_key, secp256k1_nonce_function_rfc6979, NULL)) {
            int i;
            for (i = 0; i < 32; i++) {
                sig[i] = signature.data[32 - i - 1];
                sig[i + 32] = signature.data[64 - i - 1];
            }
            return 0;
        } else {
            return 1;
        }
    }

    else if (curve == ECC_CURVE_uECC_secp256k1 || curve == ECC_CURVE_uECC_nist_p) {
        uint8_t tmp[32 + 32 + 64];
        SHA256_HashContext sha_ctx = {{&init_SHA256, &update_SHA256, &finish_SHA256, 64, 32, tmp}};
        if (curve == ECC_CURVE_uECC_nist_p) {
            return !uECC_sign_deterministic(private_key, data, SHA256_DIGEST_LENGTH, &sha_ctx.uECC,
                                            sig, uECC_secp256r1());
        } else {
            return !uECC_sign_deterministic(private_key, data, SHA256_DIGEST_LENGTH, &sha_ctx.uECC,
                                            sig, uECC_secp256k1());
        }
    }

    return 1;
}


int ecc_sign(const ecc_curve_id curve, const uint8_t *private_key, const uint8_t *msg,
             uint32_t msg_len, uint8_t *sig)
{
    uint8_t hash[SHA256_DIGEST_LENGTH];
    sha256_Raw(msg, msg_len, hash);
    return ecc_sign_digest(curve, private_key, hash, sig);
}


int ecc_sign_double(const ecc_curve_id curve, const uint8_t *privateKey,
                    const uint8_t *msg, uint32_t msg_len, uint8_t *sig)
{
    uint8_t hash[SHA256_DIGEST_LENGTH];
    sha256_Raw(msg, msg_len, hash);
    sha256_Raw(hash, SHA256_DIGEST_LENGTH, hash);
    return ecc_sign_digest(curve, privateKey, hash, sig);
}


static int ecc_uECC_read_pubkey(const ecc_curve_id curve, const uint8_t *publicKey,
                                uint8_t *public_key_64)
{
    if (publicKey[0] == 0x04) {
        memcpy(public_key_64, publicKey + 1, 64);
        return 1;
    }

    else if (publicKey[0] == 0x02 || publicKey[0] == 0x03) { // compute missing y coords
        if (curve == ECC_CURVE_uECC_nist_p) {
            uECC_decompress(publicKey, public_key_64, uECC_secp256r1());
        } else {
            uECC_decompress(publicKey, public_key_64, uECC_secp256k1());
        }
        return 1;
    }
    // error
    return 0;
}


static int ecc_verify_digest(const ecc_curve_id curve, const uint8_t *public_key,
                             const uint8_t *hash, const uint8_t *sig)
{
    if (curve == ECC_CURVE_libsecp256k1) {
        int public_key_len;
        secp256k1_ecdsa_signature signature, signorm;
        secp256k1_pubkey pubkey;

        if (!ctx) {
            ecc_context_init();
        }

        int i;
        for (i = 0; i < 32; i++) {
            signature.data[32 - i - 1] = sig[i];
            signature.data[64 - i - 1] = sig[i + 32];
        }

        if (public_key[0] == 0x04) {
            public_key_len = 65;
        } else if (public_key[0] == 0x02 || public_key[0] == 0x03) {
            public_key_len = 33;
        } else {
            return 1;
        }

        if (!secp256k1_ec_pubkey_parse(ctx, &pubkey, public_key, public_key_len)) {
            return 1;
        }

        secp256k1_ecdsa_signature_normalize(ctx, &signorm, &signature);

        if (!secp256k1_ecdsa_verify(ctx, &signorm, (const unsigned char *)hash, &pubkey)) {
            return 1;
        }

        return 0; // success
    }

    else if (curve == ECC_CURVE_uECC_nist_p) {
        uint8_t public_key_64[64];
        ecc_uECC_read_pubkey(curve, public_key, public_key_64);
        return !uECC_verify(public_key_64, hash, SHA256_DIGEST_LENGTH, sig, uECC_secp256r1());
    }

    else if (curve == ECC_CURVE_uECC_secp256k1) {
        uint8_t public_key_64[64];
        ecc_uECC_read_pubkey(curve, public_key, public_key_64);
        return !uECC_verify(public_key_64, hash, SHA256_DIGEST_LENGTH, sig, uECC_secp256k1());
    }

    return 1; // fail
}


int ecc_verify(const ecc_curve_id curve, const uint8_t *public_key,
               const uint8_t *signature, const uint8_t *msg, uint32_t msg_len)
{
    uint8_t hash[SHA256_DIGEST_LENGTH];
    sha256_Raw(msg, msg_len, hash);
    return ecc_verify_digest(curve, public_key, hash, signature);
}


int ecc_generate_private_key(const ecc_curve_id curve, uint8_t *private_child,
                             const uint8_t *private_master, const uint8_t *z)
{
    if (curve == ECC_CURVE_libsecp256k1) {
        memcpy(private_child, private_master, 32);
        return secp256k1_ec_privkey_tweak_add(ctx, (unsigned char *)private_child,
                                              (const unsigned char *)z);
    }

    else if (curve == ECC_CURVE_uECC_nist_p) {
        uECC_generate_private_key(private_child, private_master, z, uECC_secp256r1());
        return ecc_isValid(curve, private_child);
    }

    else if (curve == ECC_CURVE_uECC_secp256k1) {
        uECC_generate_private_key(private_child, private_master, z, uECC_secp256k1());
        return ecc_isValid(curve, private_child);
    }

    return 0;
}


int ecc_isValid(const ecc_curve_id curve, uint8_t *private_key)
{
    if (curve == ECC_CURVE_libsecp256k1) {
        if (!ctx) {
            ecc_context_init();
        }
        return (secp256k1_ec_seckey_verify(ctx, (const unsigned char *)private_key));
    }

    else if (curve == ECC_CURVE_uECC_nist_p) {
        return uECC_isValid(private_key, uECC_secp256r1());
    }

    else if (curve == ECC_CURVE_uECC_secp256k1) {
        return uECC_isValid(private_key, uECC_secp256k1());
    }

    return 0;
}


static void ecc_libsecp256k1_get_pubkey(const uint8_t *private_key, uint8_t *public_key,
                                        size_t public_key_len, int compressed)
{
    secp256k1_pubkey pubkey;
    memset(public_key, 0, public_key_len);

    if (!ctx) {
        ecc_context_init();
    }

    else if (!secp256k1_ec_pubkey_create(ctx, &pubkey, (const unsigned char *)private_key)) {
        return;
    }

    else if (!secp256k1_ec_pubkey_serialize(ctx, public_key, &public_key_len, &pubkey,
                                            compressed)) {
        return;
    }
}


void ecc_get_public_key65(const ecc_curve_id curve, const uint8_t *private_key,
                          uint8_t *public_key)
{
    if (curve == ECC_CURVE_libsecp256k1) {
        ecc_libsecp256k1_get_pubkey(private_key, public_key, 65, SECP256K1_EC_UNCOMPRESSED);
    }

    else if (curve == ECC_CURVE_uECC_nist_p) {
        uint8_t *p = public_key;
        p[0] = 0x04;
        uECC_compute_public_key(private_key, p + 1, uECC_secp256r1());
    }

    else if (curve == ECC_CURVE_uECC_secp256k1) {
        uint8_t *p = public_key;
        p[0] = 0x04;
        uECC_compute_public_key(private_key, p + 1, uECC_secp256k1());
    }
}


void ecc_get_public_key33(const ecc_curve_id curve, const uint8_t *private_key,
                          uint8_t *public_key)
{
    if (curve == ECC_CURVE_libsecp256k1) {
        ecc_libsecp256k1_get_pubkey(private_key, public_key, 33, SECP256K1_EC_COMPRESSED);
    }

    else if (curve == ECC_CURVE_uECC_nist_p) {
        uint8_t public_key_long[64];
        uECC_compute_public_key(private_key, public_key_long, uECC_secp256r1());
        uECC_compress(public_key_long, public_key, uECC_secp256r1());
    }

    else if (curve == ECC_CURVE_uECC_secp256k1) {
        uint8_t public_key_long[64];
        uECC_compute_public_key(private_key, public_key_long, uECC_secp256k1());
        uECC_compress(public_key_long, public_key, uECC_secp256k1());
    }
}


int ecc_ecdh(const ecc_curve_id curve, const uint8_t *pair_pubkey,
             const uint8_t *rand_privkey, uint8_t *ecdh_secret)
{
    if (curve == ECC_CURVE_libsecp256k1) {
        uint8_t ecdh_secret_compressed[33];
        secp256k1_pubkey pubkey_secp;

        if (!rand_privkey || !pair_pubkey) {
            return 1;
        }

        if (!ctx) {
            ecc_context_init();
        }

        if (!secp256k1_ec_pubkey_parse(ctx, &pubkey_secp, pair_pubkey, 33)) {
            return 1;
        }

        if (!secp256k1_ecdh(ctx, ecdh_secret_compressed, &pubkey_secp, rand_privkey)) {
            return 1;
        }

        sha256_Raw(ecdh_secret_compressed + 1, 32, ecdh_secret);
        sha256_Raw(ecdh_secret, 32, ecdh_secret);

        return 0; // success
    }


    else if (curve == ECC_CURVE_uECC_secp256k1 || curve == ECC_CURVE_uECC_nist_p) {
        uint8_t public_key[64], ret;
        if (curve == ECC_CURVE_uECC_nist_p) {
            uECC_decompress(pair_pubkey, public_key, uECC_secp256r1());
            ret = uECC_shared_secret(public_key, rand_privkey, ecdh_secret, uECC_secp256r1());
        } else {
            uECC_decompress(pair_pubkey, public_key, uECC_secp256k1());
            ret = uECC_shared_secret(public_key, rand_privkey, ecdh_secret, uECC_secp256k1());
        }
        if (ret) {
            sha256_Raw(ecdh_secret, 32, ecdh_secret);
            sha256_Raw(ecdh_secret, 32, ecdh_secret);
            return 0;
        } else {
            return 1;
        }
    }

    return 1; // fail
}


int ecc_sig_to_der(const uint8_t *sig, uint8_t *der)
{
    int i;
    uint8_t *p = der, *len, *len1, *len2;
    *p = 0x30;
    p++; // sequence
    *p = 0x00;
    len = p;
    p++; // len(sequence)

    *p = 0x02;
    p++; // integer
    *p = 0x00;
    len1 = p;
    p++; // len(integer)

    // process R
    i = 0;
    while (sig[i] == 0 && i < 32) {
        i++; // skip leading zeroes
    }
    if (sig[i] >= 0x80) { // put zero in output if MSB set
        *p = 0x00;
        p++;
        *len1 = *len1 + 1;
    }
    while (i < 32) { // copy bytes to output
        *p = sig[i];
        p++;
        *len1 = *len1 + 1;
        i++;
    }

    *p = 0x02;
    p++; // integer
    *p = 0x00;
    len2 = p;
    p++; // len(integer)

    // process S
    i = 32;
    while (sig[i] == 0 && i < 64) {
        i++; // skip leading zeroes
    }
    if (sig[i] >= 0x80) { // put zero in output if MSB set
        *p = 0x00;
        p++;
        *len2 = *len2 + 1;
    }
    while (i < 64) { // copy bytes to output
        *p = sig[i];
        p++;
        *len2 = *len2 + 1;
        i++;
    }

    *len = *len1 + *len2 + 4;
    return *len + 2;
}


