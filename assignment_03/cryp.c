#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/rand.h>

#include "cryp.h"
#include "dbgutil.h"
#include "fileutil.h"

extern int debug;

void handle_openssl_error(const char* context)
{
    dbg_perror("OpenSSL failed: %s", context);
}

int do_encrypt(
    const unsigned char* key_material, long key_material_len,
    const unsigned char* plaintext, long plaintext_len,
    const char* out_filename,
    const char* tag_filename
)
{
    // keygen
    unsigned char derived_key[AES_KEY_LEN];
    unsigned char iv[IV_LEN];

    unsigned char tag[TAG_LEN];

    unsigned char* ciphertext = NULL;
    int ciphertext_len = 0;

    EVP_CIPHER_CTX* ctx = NULL;
    EVP_MAC* hmac = NULL;
    EVP_MAC_CTX* hctx = NULL;

    OSSL_PARAM params[2];

    int len = 0;
    int ret = 2;


    // derive AES/HMAC key from the key material
    int n = EVP_BytesToKey(
        EVP_aes_256_ctr(),   // cipher whose key-size we want
        EVP_sha256(),        // digest to expand the bytes
        NULL,                // no salt
        key_material,        // *raw* pass-phrase bytes
        key_material_len,    // length of pass-phrase
        1,                   // iteration count 1 bc we dont need to slow this down for fun this is just to get 32 byte keys
        derived_key,         // OUT: AES-256 key
        NULL                 // do not generate IV deterministically
    );

    // generate a random IV
    if (RAND_bytes(iv, IV_LEN) != 1)
    {
        handle_openssl_error("failed to generate IV");
        goto cleanup;
    }

    // check the length of the derived key
    // this should be 32 bytes for AES-256
    if (n != AES_KEY_LEN)
    {
        handle_openssl_error("EVP_BytesToKey failed for AES/HMAC key\n");
        goto cleanup;
    }

    // create the AES encyption
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
    {
        handle_openssl_error("failed to create EVP context");
        goto cleanup;
    }

    // initialize the encryption operation
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_ctr(), NULL, derived_key, iv) != 1)
    {
        handle_openssl_error("failed to initialize encryption");
        goto cleanup;
    }

    // alloc memory for ciphertext
    // for ctx, max len of cipheretext is plaintext_len + block_size
    ciphertext = malloc(plaintext_len + EVP_CIPHER_CTX_block_size(ctx));
    if (!ciphertext)
    {
        dbg_perror("failed to allocate memory for ciphertext");
        goto cleanup;
    }

    // encrypt the plaintext
    if (EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len) != 1)
    {
        handle_openssl_error("encryption update failed");
        goto cleanup;
    }
    // store the length of ciphertext
    ciphertext_len = len;

    if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1)
    {
        handle_openssl_error("encryption finalization failed");
        goto cleanup;
    }
    // add finalization (last block + pad) length to ciphertext length
    ciphertext_len += len;

    // write the IV and ciphertext to the output file
    size_t out_buffer_len = IV_LEN + ciphertext_len;
    unsigned char* out_buffer = malloc(out_buffer_len);
    if (!out_buffer)
    {
        dbg_perror("failed to allocate memory for output buffer");
        goto cleanup;
    }
    memcpy(out_buffer, iv, IV_LEN);
    memcpy(out_buffer + IV_LEN, ciphertext, ciphertext_len);

    // write the IV and ciphertext to the output file
    if (write_file(out_filename, out_buffer, out_buffer_len) != 0)
    {
        dbg_perror("failed to write to output file");
        goto cleanup;
    }

    // load the HMAC algorithm
    hmac = EVP_MAC_fetch(NULL, "HMAC", NULL);
    if (!hmac)
    {
        handle_openssl_error("failed to fetch HMAC");
        goto cleanup;
    }

    // create the HMAC context
    hctx = EVP_MAC_CTX_new(hmac);
    if (!hctx)
    {
        handle_openssl_error("failed to create HMAC context");
        goto cleanup;
    }

    // set HMAC digest algorithm ot SHA256
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, "SHA256", 0);
    params[1] = OSSL_PARAM_construct_end();

    // initialize the HMAC context
    // key_material is the key, key_material_len is the length of the key
    // params is the parameters for the HMAC algorithm
    if (!EVP_MAC_init(hctx, derived_key, AES_KEY_LEN, params))
    {
        handle_openssl_error("failed to initialize HMAC");
        goto cleanup;
    }

    // update the HMAC context with the ciphertext AND IV
    if (!EVP_MAC_update(hctx, out_buffer, out_buffer_len))
    {
        handle_openssl_error("HMAC update failed");
        goto cleanup;
    }

    size_t tag_len;
    // finalize the HMAC computation
    if (!EVP_MAC_final(hctx, tag, &tag_len, TAG_LEN))
    {
        handle_openssl_error("HMAC finalization failed");
        goto cleanup;
    }

    // check the length of the HMAC output ? why
    if (tag_len != TAG_LEN)
    {
        dbg_perror("HMAC tag length mismatch");
        goto cleanup;
    }

    // write the HMAC tag to the tag file
    if (write_file(tag_filename, tag, TAG_LEN) != 0)
    {
        dbg_perror("failed to write to tag file");
        goto cleanup;
    }

    ret = 0;

cleanup:
    // free the allocated memory and contexts
    EVP_CIPHER_CTX_free(ctx);
    EVP_MAC_CTX_free(hctx);
    EVP_MAC_free(hmac);
    free(ciphertext);
    free(out_buffer);
    return ret;
}

int do_decrypt(
    const unsigned char* key_material, long key_material_len,
    const unsigned char* ciphertext_with_iv, long ciphertext_with_iv_len,
    const char* out_filename,
    const char* tag_filename
)
{
    // keygen
    unsigned char derived_key[AES_KEY_LEN];
    unsigned char iv[IV_LEN];

    unsigned char expected_tag[TAG_LEN];
    unsigned char calculated_tag[TAG_LEN];

    const unsigned char* ciphertext_data = NULL;
    long ciphertext_len = 0;

    long read_tag_len = 0;

    unsigned char* plaintext = NULL;
    int plaintext_len = 0;

    EVP_CIPHER_CTX* ctx = NULL;
    EVP_MAC* hmac = NULL;
    EVP_MAC_CTX* hctx = NULL;

    OSSL_PARAM params[2];

    int len = 0;
    int ret = 2;

    // ciphertext length sanity check
    if (ciphertext_with_iv_len < IV_LEN)
    {
        dbg_perror("input ciphertext buffer is too short to contain IV (%ld bytes)", ciphertext_with_iv_len);
        goto cleanup;
    }

    // read the tag file
    read_tag_len = read_file_max_n_chars(tag_filename, expected_tag, TAG_LEN);
    if (read_tag_len == -1)
    {
        dbg_perror("failed to read tag file: %s", tag_filename);
        goto cleanup;
    }

    // check the length of the tag file to verify HMAC (stored hmac being modified counts as tampering, ig....?)
    if (read_tag_len != TAG_LEN)
    {
        dbg_perror("tag file '%s' has incorrect size (expected %d, got %ld)", tag_filename, TAG_LEN, read_tag_len);
        ret = 1;
        goto cleanup;
    }

    // extract the IV from the ciphertext_with_iv buffer
    memcpy(iv, ciphertext_with_iv, IV_LEN);
    ciphertext_data = ciphertext_with_iv + IV_LEN;
    ciphertext_len = ciphertext_with_iv_len - IV_LEN;

    // derive AES/HMAC key from the key material
    int n = EVP_BytesToKey(
        EVP_aes_256_ctr(),   // cipher whose key-size we want
        EVP_sha256(),        // digest to expand the bytes
        NULL,                // optional salt (8 bytes)
        key_material,        // *raw* pass-phrase bytes
        key_material_len,    // length of pass-phrase
        1,                   // iteration count 1 bc we dont need to slow this down for fun this is just to get 32 byte keys
        derived_key,         // OUT: AES-256 key
        NULL                 // do not generate IV deterministically, use iv in ciphertext_with_iv
    );

    // check the length of the derived key
    // this should be 32 bytes for AES-256
    if (n != AES_KEY_LEN)
    {
        handle_openssl_error("EVP_BytesToKey failed for AES/HMAC key\n");
        goto cleanup;
    }

    // load the HMAC algorithm
    hmac = EVP_MAC_fetch(NULL, "HMAC", NULL);
    if (!hmac)
    {
        handle_openssl_error("failed to fetch HMAC");
        goto cleanup;
    }

    // create the HMAC context
    hctx = EVP_MAC_CTX_new(hmac);
    if (!hctx)
    {
        handle_openssl_error("failed to create HMAC context");
        goto cleanup;
    }

    // set HMAC digest algorithm to SHA256
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, "SHA256", 0);
    params[1] = OSSL_PARAM_construct_end();

    // initialize the HMAC context
    if (!EVP_MAC_init(hctx, derived_key, AES_KEY_LEN, params))
    {
        handle_openssl_error("failed to initialize HMAC");
        goto cleanup;
    }

    // update the HMAC context
    // again, HMAC should check authenticity of the ciphertext AND IV
    // if not, IV can be tampered with, thus modifying the decrypted plaintext
    if (!EVP_MAC_update(hctx, ciphertext_with_iv, ciphertext_with_iv_len))
    {
        handle_openssl_error("HMAC update failed");
        goto cleanup;
    }

    // finalize the HMAC computation
    size_t calculated_tag_len;
    if (!EVP_MAC_final(hctx, calculated_tag, &calculated_tag_len, TAG_LEN))
    {
        handle_openssl_error("HMAC finalization failed");
        goto cleanup;
    }

    // check the length of the HMAC output
    if (calculated_tag_len != TAG_LEN)
    {
        dbg_perror("calculated HMAC output length mismatch");
        ret = 1;
        goto cleanup;
    }

    // compare the expected and calculated HMAC tags with CRYPTO_memcmp wooo fancy
    if (CRYPTO_memcmp(expected_tag, calculated_tag, TAG_LEN) != 0)
    {
        dbg_perror("HMAC verification failed");
        ret = 1;
        goto cleanup;
    }

    // if we didnt jump to cleanup, we have a valid tag
    // decrypt the ciphertext

    // create the AES decryption context
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
    {
        handle_openssl_error("failed to create EVP context");
        goto cleanup;
    }

    // initialize the decryption operation
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_ctr(), NULL, (const unsigned char*)derived_key, iv) != 1)
    {
        handle_openssl_error("failed to initialize decryption");
        goto cleanup;
    }

    // alloc memory for plaintext
    plaintext = malloc(ciphertext_len + EVP_CIPHER_CTX_block_size(ctx));
    if (!plaintext)
    {
        dbg_perror("failed to allocate memory for plaintext");
        goto cleanup;
    }

    // update decryption operation
    if (EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext_data, ciphertext_len) != 1)
    {
        handle_openssl_error("decryption update failed");
        goto cleanup;
    }
    // store the length of plaintext so far
    plaintext_len = len;

    // finalize decryption operation
    if (EVP_DecryptFinal_ex(ctx, plaintext + len, &len) != 1)
    {
        handle_openssl_error("decryption finalization failed");
        goto cleanup;
    }
    // add final decrypted blocks length to plaintext length
    plaintext_len += len;

    // write the plaintext to the output file
    if (write_file(out_filename, plaintext, plaintext_len) != 0)
    {
        goto cleanup;
    }

    ret = 0;

cleanup:
    // free the allocated memory and contexts
    EVP_CIPHER_CTX_free(ctx);
    EVP_MAC_CTX_free(hctx);
    EVP_MAC_free(hmac);
    free(plaintext);
    return ret;
}

int main(int argc, char* argv[])
{
    // custom util for debugging
    // if 0, no all dbg_*** functions do nothing
    // if 1, all dbg_*** functions print to stderr
    debug = 0;

    if (argc < 10)
    {
        printf(ERROR_MSG);
        return 2;
    }

    enum mode m;

    if (strcmp(LIT_ENCRYPT_MODE_ARG, argv[1]) == 0) { m = ENCRYPT; }
    else if (strcmp(LIT_DECRYPT_MODE_ARG, argv[1]) == 0) { m = DECRYPT; }
    else
    {
        dbg_perror("invalid mode: %s", argv[1]);
        printf(ERROR_MSG);
        return 2;
    }

    // ./cryp enc -key shared.key -in original.txt -out encrypted.txt -tag encrypted.tag
    // ./cryp dec -key shared.key -in encrypted.txt -tag encrypted.tag -out decrypted.txt
    // argc = 10

    char* arg_key = 0;
    char* arg_in = 0;
    char* arg_out = 0;
    char* arg_tag = 0;

    for (int i = 2; i < argc; i += 2)
    {
        if (strcmp("-key", argv[i]) == 0) { arg_key = argv[i + 1]; }
        else if (strcmp("-in", argv[i]) == 0) { arg_in = argv[i + 1]; }
        else if (strcmp("-out", argv[i]) == 0) { arg_out = argv[i + 1]; }
        else if (strcmp("-tag", argv[i]) == 0) { arg_tag = argv[i + 1]; }
        else
        {
            dbg_perror("invalid argument: %s", argv[i]);
            printf(ERROR_MSG);
            return 2;
        }
    }

    if (arg_key == NULL || arg_in == NULL || arg_out == NULL || arg_tag == NULL) { dbg_perror("unspecified option(s) present\n"); }

    // read in files into buffers
    unsigned char* buffer_key = 0;
    unsigned char* buffer_in = 0;

    long key_len = read_file(arg_key, &buffer_key);
    long in_len = read_file(arg_in, &buffer_in);

    if (key_len < 0 || in_len < 0)
    {
        if (key_len < 0) { dbg_perror("failed to read file: %s", arg_key); }
        else if (in_len < 0) { dbg_perror("failed to read file: %s", arg_in); }
        printf(ERROR_MSG);
        return 2;
    }

    int status = 0;
    if (m == ENCRYPT)
    {
        status = do_encrypt(buffer_key, key_len, buffer_in, in_len, arg_out, arg_tag);
        if (status != 0)
        {
            dbg_perror("MAIN: encryption failed with code: %d", status);
            printf(ERROR_MSG);
            return 2;
        }
    }
    else if (m == DECRYPT)
    {
        status = do_decrypt(buffer_key, key_len, buffer_in, in_len, arg_out, arg_tag);
        if (status != 0)
        {
            // hmac verification failed
            if (status == 1)
            {
                dbg_perror("MAIN: HMAC verification failed");
                printf("VERIFICATION FAILURE\n");
                return 1;
            }
            // general error
            else
            {
                dbg_perror("MAIN: decryption failed with code: %d", status);
                printf(ERROR_MSG);
                return 2;
            }
        }
    }

    fflush(stdout);

    // free the allocated buffers:
    free(buffer_key);
    free(buffer_in);
}