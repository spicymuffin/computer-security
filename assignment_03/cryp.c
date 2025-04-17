/* cryp.c  – authenticated encryption/decryption with AES‑256‑CBC + HMAC‑SHA‑256
 *
 * Build:   gcc cryp.c -o cryp -lcrypto
 * Usage:   ./cryp enc -key shared.key -in plain.txt  -out cipher.bin -tag cipher.tag
 *          ./cryp dec -key shared.key -in cipher.bin -out plain.txt  -tag cipher.tag
 *
 * Exit codes:
 *   0  success
 *   1  VERIFICATION FAILURE          (printed to stdout)
 *   2  ERROR                         (printed to stdout)
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/err.h>

#define IV_LEN   16          /* AES‑256‑CBC IV length  */
#define KEY_LEN  32          /* AES‑256 key length     */
#define TAG_LEN  32          /* HMAC‑SHA‑256 length    */

static void bail(int code, const char *msg)
{
    if (msg) puts(msg);      /* must end with newline per spec           */
    exit(code);
}

/* Read an entire file into memory (binary‑safe).  Returns length via *len. */
static unsigned char *read_file(const char *path, size_t *len)
{
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    if (fseek(f, 0, SEEK_END)) { fclose(f); return NULL; }
    long sz = ftell(f);
    if (sz < 0) { fclose(f); return NULL; }
    rewind(f);

    unsigned char *buf = malloc(sz ?: 1);
    if (!buf) { fclose(f); return NULL; }
    if (fread(buf, 1, sz, f) != (size_t)sz) { fclose(f); free(buf); return NULL; }
    fclose(f);
    *len = sz;
    return buf;
}

static int write_file(const char *path, const unsigned char *buf, size_t len)
{
    FILE *f = fopen(path, "wb");
    if (!f) return 0;
    int ok = fwrite(buf, 1, len, f) == len;
    fclose(f);
    return ok;
}

/* Hex helpers for tag files ------------------------------------------------*/
static int hex_decode(const char *hex, unsigned char *out, size_t expect_len)
{
    for (size_t i = 0; i < expect_len; i++) {
        unsigned int byte;
        if (sscanf(&hex[i*2], "%2x", &byte) != 1) return 0;
        out[i] = (unsigned char)byte;
    }
    return 1;
}

static char *hex_encode(const unsigned char *buf, size_t len)
{
    char *hex = malloc(len*2 + 1);
    if (!hex) return NULL;
    for (size_t i = 0; i < len; i++)
        sprintf(&hex[i*2], "%02x", buf[i]);
    return hex;
}

/* Constant‑time equality */
static int ct_equal(const unsigned char *a, const unsigned char *b, size_t len)
{
    unsigned char diff = 0;
    for (size_t i = 0; i < len; i++) diff |= a[i] ^ b[i];
    return diff == 0;
}

/* Derive 32‑byte AES key from arbitrary key material with SHA‑256. */
static int derive_key(const unsigned char *src, size_t src_len, unsigned char key[KEY_LEN])
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) return 0;
    int ok = EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) &&
             EVP_DigestUpdate(ctx, src, src_len) &&
             EVP_DigestFinal_ex(ctx, key, NULL);
    EVP_MD_CTX_free(ctx);
    return ok;
}

/* --------------------------- ENC ----------------------------------------- */
static int do_encrypt(const char *keyfile, const char *infile,
                      const char *outfile, const char *tagfile)
{
    size_t klen, plen;
    unsigned char *kbuf = read_file(keyfile, &klen);
    unsigned char *plain = read_file(infile, &plen);
    if (!kbuf || !plain) goto error;

    unsigned char key[KEY_LEN], iv[IV_LEN];
    if (!derive_key(kbuf, klen, key) || !RAND_bytes(iv, IV_LEN)) goto error;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) goto error;
    int outlen1, outlen2;
    unsigned char *cipher = malloc(plen + EVP_MAX_BLOCK_LENGTH);
    if (!cipher) goto err_ctx;

    if (!EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) ||
        !EVP_EncryptUpdate(ctx, cipher, &outlen1, plain, plen) ||
        !EVP_EncryptFinal_ex(ctx, cipher + outlen1, &outlen2))
        goto err_ctx;
    size_t clen = outlen1 + outlen2;

    /* Build ciphertext file = IV || C */
    unsigned char *outbuf = malloc(IV_LEN + clen);
    if (!outbuf) goto err_ctx;
    memcpy(outbuf, iv, IV_LEN);
    memcpy(outbuf + IV_LEN, cipher, clen);
    if (!write_file(outfile, outbuf, IV_LEN + clen)) goto err_ctx2;

    /* HMAC tag */
    unsigned char tag[TAG_LEN];
    if (!HMAC(EVP_sha256(), key, KEY_LEN, outbuf, IV_LEN + clen, tag, NULL))
        goto err_ctx2;
    char *hex = hex_encode(tag, TAG_LEN);
    if (!hex || !write_file(tagfile, (unsigned char *)hex, TAG_LEN*2))
        goto err_ctx2;

    /* clean up & return success */
    free(hex); free(outbuf); free(cipher); EVP_CIPHER_CTX_free(ctx);
    free(kbuf); free(plain);
    return 0;

err_ctx2:
    free(outbuf);
err_ctx:
    free(cipher); EVP_CIPHER_CTX_free(ctx);
error:
    free(kbuf); free(plain);
    return 2;
}

/* --------------------------- DEC ----------------------------------------- */
static int do_decrypt(const char *keyfile, const char *infile,
                      const char *outfile, const char *tagfile)
{
    size_t klen, clen_and_iv_len, tag_hex_len;
    unsigned char *kbuf = read_file(keyfile, &klen);
    unsigned char *cbuf = read_file(infile, &clen_and_iv_len);
    unsigned char *tag_hex = read_file(tagfile, &tag_hex_len);
    if (!kbuf || !cbuf || !tag_hex || tag_hex_len != TAG_LEN*2) goto error;

    unsigned char key[KEY_LEN], tag[TAG_LEN];
    if (!derive_key(kbuf, klen, key) ||
        !hex_decode((char *)tag_hex, tag, TAG_LEN)) goto error;

    /* Verify HMAC first */
    unsigned char calc[TAG_LEN];
    if (!HMAC(EVP_sha256(), key, KEY_LEN, cbuf, clen_and_iv_len, calc, NULL))
        goto error;
    if (!ct_equal(calc, tag, TAG_LEN)) {
        puts("VERIFICATION FAILURE");
        exit(1);
    }

    /* Extract IV & ciphertext */
    if (clen_and_iv_len < IV_LEN) goto error;
    unsigned char *iv = cbuf;
    unsigned char *cipher = cbuf + IV_LEN;
    size_t clen = clen_and_iv_len - IV_LEN;

    /* Decrypt */
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) goto error;
    unsigned char *plain = malloc(clen);              /* CBC ≤ same size */
    if (!plain) { EVP_CIPHER_CTX_free(ctx); goto error; }

    int outlen1, outlen2;
    if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) ||
        !EVP_DecryptUpdate(ctx, plain, &outlen1, cipher, clen) ||
        !EVP_DecryptFinal_ex(ctx, plain + outlen1, &outlen2)) {
        EVP_CIPHER_CTX_free(ctx); free(plain); goto error;
    }
    size_t plen = outlen1 + outlen2;

    int ok = write_file(outfile, plain, plen);
    EVP_CIPHER_CTX_free(ctx); free(plain);
    if (!ok) goto error;

    free(kbuf); free(cbuf); free(tag_hex);
    return 0;

error:
    puts("ERROR");
    exit(2);
}

/* --------------------------- main ---------------------------------------- */
static const char *get_opt(int *i, int argc, char **argv)
{
    if (*i + 1 >= argc) bail(2, "ERROR");
    return argv[++*i];
}

int main(int argc, char **argv)
{
    if (argc < 2) bail(2, "ERROR");
    int enc = !strcmp(argv[1], "enc");
    int dec = !strcmp(argv[1], "dec");
    if (!enc && !dec) bail(2, "ERROR");

    const char *keyfile = NULL, *infile = NULL, *outfile = NULL, *tagfile = NULL;

    for (int i = 2; i < argc; i++) {
        if (!strcmp(argv[i], "-key")) keyfile = get_opt(&i, argc, argv);
        else if (!strcmp(argv[i], "-in")) infile = get_opt(&i, argc, argv);
        else if (!strcmp(argv[i], "-out")) outfile = get_opt(&i, argc, argv);
        else if (!strcmp(argv[i], "-tag")) tagfile = get_opt(&i, argc, argv);
        else bail(2, "ERROR");
    }
    if (!keyfile || !infile || !outfile || !tagfile)
        bail(2, "ERROR");

    OPENSSL_init_crypto(0, NULL);

    int ret = enc ? do_encrypt(keyfile, infile, outfile, tagfile)
                  : do_decrypt(keyfile, infile, outfile, tagfile);
    if (ret == 0) return 0;       /* success already handled */
    puts("ERROR");
    return 2;
}
