#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

#include <libelf.h>
#include <gelf.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/decoder.h>

#include "dbgutil.h"
#include "signtool.h"
#include "cas4109.h"
#include "fileutil.h"

extern int debug;

// the executable is read into md,
// the length of the md is mdlen
// signing_key is initialized with the private key
// sig is the signature buffer
// siglen is the length of the signature
int do_sign(unsigned char* md, size_t mdlen, EVP_PKEY* signing_key, unsigned char** sig, size_t* siglen)
{
    int return_code = -1;
    EVP_PKEY_CTX* ctx;

    /*
    * NB: assumes signing_key and md are set up before the next
    * step. signing_key must be an RSA private key and md must
    * point to the SHA-256 digest to be signed.
    */
    if ((ctx = EVP_PKEY_CTX_new(signing_key, NULL)) <= 0)
    {
        dbg_perror("do_sign failed: EVP_PKEY_CTX_new");
        goto sign_err;
    }

    if (EVP_PKEY_sign_init(ctx) <= 0)
    {
        dbg_perror("do_sign failed: EVP_PKEY_sign_init");
        goto sign_err;
    }

    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0)
    {
        dbg_perror("do_sign failed: EVP_PKEY_CTX_set_rsa_padding");
        goto sign_err;
    }

    if (EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha256()) <= 0)
    {
        dbg_perror("do_sign failed: EVP_PKEY_CTX_set_signature_md");
        goto sign_err;
    }

    // determine the length of the signature
    if (EVP_PKEY_sign(ctx, NULL, siglen, md, mdlen) <= 0)
    {
        dbg_perror("do_sign failed: EVP_PKEY_sign");
        goto sign_err;
    }

    if ((sig = OPENSSL_malloc(*siglen)) == NULL)
    {
        dbg_perror("do_sign failed: OPENSSL_malloc");
        goto sign_err;
    }

    // signature is siglen bytes written to buffer sig
    if (EVP_PKEY_sign(ctx, *sig, siglen, md, mdlen) <= 0)
    {
        goto sign_err;
    }

    return 0;

sign_err:
    EVP_PKEY_CTX_free(ctx);
    return return_code;
}

int read_key(const char* key_file, int private, EVP_PKEY** key)
{
    unsigned char* keybuf = NULL;

    int return_code = -1;

    // read the key file into a buffer
    long keylen = read_file(key_file, &keybuf);
    if (keylen < 0)
    {
        dbg_perror("read_key failed: read_file");
        goto read_key_err;
    }

    OSSL_DECODER_CTX* dctx = NULL;

    // read private or public key
    if (private)
    {
        dctx = OSSL_DECODER_CTX_new_for_pkey(key, "PEM", NULL, "RSA", OSSL_KEYMGMT_SELECT_PRIVATE_KEY, NULL, NULL);
    }
    else
    {
        dctx = OSSL_DECODER_CTX_new_for_pkey(key, "PEM", NULL, "RSA", OSSL_KEYMGMT_SELECT_PUBLIC_KEY, NULL, NULL);
    }

    if (dctx == NULL)
    {
        dbg_perror("read_key failed: OSSL_DECODER_CTX_new_for_pkey");
        goto read_key_err;
    }

    // ossl decoder promises to not change the data through pointer p
    const unsigned char* p = keybuf;
    size_t l = (size_t)keylen;

    if (!OSSL_DECODER_from_data(dctx, &p, &l))
    {
        dbg_perror("read_key failed: OSSL_DECODER_from_data");
        goto read_key_err;
    }

    return 0;

read_key_err:
    if (dctx)
    {
        OSSL_DECODER_CTX_free(dctx);
    }
    if (keybuf)
    {
        free(keybuf);
    }

    return return_code;
}

// signtool
// CLI:
// ./signtool sign -e <path to executable> -k <path to private_key.pem>
// ./signtool verify -e <path to signed executable> -k <path to public_key.pem>

int main(int argc, char* argv[])
{
    // custom util for debugging
    // if 0, no all dbg_*** functions do nothing
    // if 1, all dbg_*** functions print to stderr
    debug = 0;

    char* arg_file;
    char* arg_key;

    enum mode m;

    if (strcmp(argv[1], "sign"))
    {
        m = SIGN;
    }
    else if (strcmp(argv[1], "verify"))
    {
        m = VERIFY;
    }

    for (int i = 2; i < argc; i += 2)
    {
        if (strcmp(argv[i], "-e"))
        {
            arg_file = argv[i + 1];
        }
        else if (strcmp(argv[i], "-k"))
        {
            arg_key = argv[i + 1];
        }
    }

    int fd;
    Elf* e;
    Elf_Kind ek;

    if (elf_version(EV_CURRENT) == EV_NONE)
    {
        dbg_perror("elfparse failed: %s", elf_errmsg(-1));
        goto err;
    }
    if ((fd = open(arg_file, O_RDONLY, 0)) < 0)
    {
        dbg_perror("open failed: %s", arg_file);
        goto err;
    }
    if ((e = elf_begin(fd, ELF_C_RDWR, NULL)) == NULL)
    {
        dbg_perror("elf_begin failed: %s", elf_errmsg(-1));
        goto err;
    }
    if ((ek = elf_kind(e)) != ELF_K_ELF)
    {
        dbg_perror("elf_kind returned non-executable: %d", ek);
        goto err;
    }

    int error_code = -1;
    int tmp;

    if (m == SIGN)
    {
        error_code = -1; // elf file not modified

        // read key
        EVP_PKEY* signing_key = NULL;
        if ((tmp = read_key(arg_key, 1, &signing_key)) != 0)
        {
            dbg_perror("read_key failed: code %d, reading %s", tmp, arg_key);
            goto sign_err;
        }

        // allocate signature section space
        size_t sig_size = SIGNATURE_LEN;

        Elf_Scn* sig_scn = elf_newscn(e);
        if (sig_scn == NULL)
        {
            dbg_perror("elf_newscn failed: %s", elf_errmsg(-1));
            goto sign_err;
        }

        Elf_Data* sig_data = elf_newdata(sig_scn);
        if (sig_data == NULL)
        {
            dbg_perror("elf_newdata failed: %s", elf_errmsg(-1));
            goto sign_err;
        }

        unsigned char* zero_buf = calloc(1, sig_size);
        if (zero_buf == NULL)
        {
            dbg_perror("calloc failed");
            goto sign_err;
        }

        sig_data->d_align = 1;              // alignment is 1 (we don't care)
        sig_data->d_buf = zero_buf;         // data buffer
        sig_data->d_size = sig_size;        // reserve space for signature
        sig_data->d_type = ELF_T_BYTE;      // type is unsigned char
        sig_data->d_version = EV_CURRENT;   // version is current

        // update the shstrtab
        size_t shstrtab_index = 0;
        if (elf_getshdrstrndx(e, &shstrtab_index) != 0)
        {
            dbg_perror("elf_getshstrndx failed: %s", elf_errmsg(-1));
            goto sign_err;
        }

        Elf_Scn* shstrtab_scn = elf_getscn(e, shstrtab_index);
        if (shstrtab_scn == NULL)
        {
            dbg_perror("elf_getscn failed: %s", elf_errmsg(-1));
            goto sign_err;
        }

        Elf_Data* shstrtab_data = elf_getdata(shstrtab_scn, NULL);
        if (shstrtab_data == NULL)
        {
            dbg_perror("elf_getdata failed: %s", elf_errmsg(-1));
            goto sign_err;
        }

        size_t unsigned_shstrtab_size = shstrtab_data->d_size;

        const char* signature_scn_name = SIGNATURE_SECTION_NAME;
        size_t signature_scn_name_len = strlen(signature_scn_name) + 1;

        Elf_Data* signed_shstrtab_data = elf_newdata(shstrtab_scn);
        if (signed_shstrtab_data == NULL)
        {
            dbg_perror("elf_newdata failed: %s", elf_errmsg(-1));
            goto sign_err;
        }
        signed_shstrtab_data->d_align = 1;
        signed_shstrtab_data->d_buf = (void*)signature_scn_name;
        signed_shstrtab_data->d_size = signature_scn_name_len;
        signed_shstrtab_data->d_type = ELF_T_BYTE;
        signed_shstrtab_data->d_version = EV_CURRENT;

        GElf_Shdr shdr;
        gelf_getshdr(sig_scn, &shdr);
        shdr.sh_name = unsigned_shstrtab_size;
        shdr.sh_type = SHT_PROGBITS;
        // shdr.sh_flags = SHF_ALLOC; // no need to load this section when runnning
        shdr.sh_addralign = 1;
        gelf_update_shdr(sig_scn, &shdr);

        // sync the updated elf file with disk
        if (elf_update(e, ELF_C_WRITE) < 0)
        {
            dbg_perror("elf_update failed: %s", elf_errmsg(-1));
            goto sign_err;
        }

        error_code = -2; // elf file modified, signature section allocated

        // read the executable file again
        unsigned char* md = NULL;
        long mdlen = read_file(arg_file, &md);
        if (mdlen < 0)
        {
            dbg_perror("read_file failed: %s", arg_file);
            goto sign_err;
        }

        // calculate signature

        // write signature to .signature section

        // save and quit
        goto success;

    sign_err:
        if (signing_key)
        {
            EVP_PKEY_free(signing_key);
        }
        if (zero_buf)
        {
            free(zero_buf);
        }
        goto err;
    }
    else if (m == VERIFY)
    {
        // read key
        EVP_PKEY* verifying_key = NULL;
        if ((tmp = read_key(arg_key, 0, &verifying_key)) != 0)
        {
            dbg_perror("read_key failed: code %d, reading %s", tmp, arg_key);
            goto err;
        }

    }

success:
    return 0;
err:
    if (e)
    {
        elf_end(e);
    }
    if (fd)
    {
        close(fd);
    }
    return error_code;
}