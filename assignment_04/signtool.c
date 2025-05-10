#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

#include <libelf.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>

#include "dbgutil.h"
#include "signtool.h"
#include "cas4109.h"
#include "fileutil.h"

extern int debug;

int do_sign()
{
    EVP_PKEY* pkey = NULL;
    EVP_PKEY_CTX* ctx = NULL;

    pkey = EVP_PKEY_CTX_new_from_name();
    ctx = EVP_PKEY_CTX_new(pkey, NULL);
    EVP_PKEY_sign_init();
    return 0;
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

    char* arg_path;
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
            arg_path = argv[i + 1];
        }
        else if (strcmp(argv[i], "-k"))
        {
            arg_path = argv[i + 1];
        }
    }

    int fd;
    Elf* e;
    char* k;
    Elf_Kind ek;

    if (elf_version(EV_CURRENT) == EV_NONE)
    {
        dbg_perror("elfparse failed: %s", elf_errmsg(-1));
        goto err;
    }
    if ((fd = open(argv[1], O_RDONLY, 0)) < 0)
    {
        dbg_perror("open failed: %s", argv[1]);
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

    if (m == SIGN)
    {
        // read the elf file (everything into a buffer)
        // read the private key

    }
    else if (m == VERIFY)
    {
        
    }

err:
    if (e)
    {
        elf_end(e);
    }
    if (fd)
    {
        close(fd);
    }
    return 2;
}