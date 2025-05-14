#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

#include <libelf.h>
#include <gelf.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/decoder.h>

#include "dbgutil.h"
#include "signtool.h"
#include "fileutil.h"
#include "cas4109.h"

extern int debug;


// computes SHA-256 hash of a buffer
// buf is the input data, len is its size
// out_digest must point to at least 32 bytes of memory
// out_len will be set to 32 on success
int hash_buffer_sha256(const unsigned char* buf, size_t len, unsigned char* out_digest, unsigned int* out_len)
{
    int ret = -1;
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) return -1;

    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) goto hash_buffer_sha256_cleanup;
    if (EVP_DigestUpdate(ctx, buf, len) != 1) goto hash_buffer_sha256_cleanup;
    if (EVP_DigestFinal_ex(ctx, out_digest, out_len) != 1) goto hash_buffer_sha256_cleanup;

    ret = 0;

hash_buffer_sha256_cleanup:
    EVP_MD_CTX_free(ctx);
    return ret;
}

// the message to sign is passed in as msg with length msglen
// the function allocates *sig and sets siglen to the signature size
// returns 0 on success, -1 on failure
int do_sign(const unsigned char* msg, size_t msglen, EVP_PKEY* signing_key, unsigned char** sig, size_t* siglen)
{
    int ret = -1;
    EVP_MD_CTX* mdctx = NULL;

    if ((mdctx = EVP_MD_CTX_new()) == NULL)
    {
        dbg_perror("do_sign failed: EVP_MD_CTX_new: %s", ERR_reason_error_string(ERR_get_error()));
        goto do_sign_cleanup;
    }

    if (EVP_DigestSignInit(mdctx, NULL, EVP_sha256(), NULL, signing_key) != 1)
    {
        dbg_perror("do_sign failed: EVP_DigestSignInit: %s", ERR_reason_error_string(ERR_get_error()));
        goto do_sign_cleanup;
    }

    if (EVP_DigestSignUpdate(mdctx, msg, msglen) != 1)
    {
        dbg_perror("do_sign failed: EVP_DigestSignUpdate: %s", ERR_reason_error_string(ERR_get_error()));
        goto do_sign_cleanup;
    }

    // first call to get signature length
    if (EVP_DigestSignFinal(mdctx, NULL, siglen) != 1)
    {
        dbg_perror("do_sign failed: EVP_DigestSignFinal (len): %s", ERR_reason_error_string(ERR_get_error()));
        goto do_sign_cleanup;
    }

    *sig = (unsigned char*)OPENSSL_malloc(*siglen);
    if (*sig == NULL)
    {
        dbg_perror("do_sign failed: OPENSSL_malloc");
        goto do_sign_cleanup;
    }

    // second call to get actual signature
    if (EVP_DigestSignFinal(mdctx, *sig, siglen) != 1)
    {
        dbg_perror("do_sign failed: EVP_DigestSignFinal (sign): %s", ERR_reason_error_string(ERR_get_error()));
        OPENSSL_free(*sig);
        *sig = NULL;
        *siglen = 0;
        goto do_sign_cleanup;
    }

    ret = 0;

do_sign_cleanup:
    if (mdctx)
        EVP_MD_CTX_free(mdctx);

    return ret;
}

Elf_Scn* find_section_by_name(Elf* elf, const char* target_name)
{
    if (!elf || !target_name) return NULL;

    size_t shstrndx;
    if (elf_getshdrstrndx(elf, &shstrndx) < 0)
    {
        dbg_perror("find_section_by_name failed: elf_getshdrstrndx: %s", elf_errmsg(-1));
        return NULL;
    }

    Elf_Scn* scn = NULL;
    while ((scn = elf_nextscn(elf, scn)) != NULL)
    {
        GElf_Shdr shdr;
        if (gelf_getshdr(scn, &shdr) != &shdr) continue;
        const char* name = elf_strptr(elf, shstrndx, shdr.sh_name);
        if (name && strcmp(name, target_name) == 0) return scn; // found
    }

    return NULL; // section not found
}

// verifies that the signature sig of length siglen
// matches the msg of length msglen using the public verify_key
// returns 1 if the signature is valid, 0 if invalid, 2 on error
int do_verify(const unsigned char* msg, size_t msglen, EVP_PKEY* verify_key, const unsigned char* sig, size_t siglen)
{
    int result = 2;
    EVP_MD_CTX* mdctx = NULL;

    if ((mdctx = EVP_MD_CTX_new()) == NULL)
    {
        dbg_perror("do_verify failed: EVP_MD_CTX_new: %s", ERR_reason_error_string(ERR_get_error()));
        goto do_verify_cleanup;
    }

    if (EVP_DigestVerifyInit(mdctx, NULL, EVP_sha256(), NULL, verify_key) != 1)
    {
        dbg_perror("do_verify failed: EVP_DigestVerifyInit: %s", ERR_reason_error_string(ERR_get_error()));
        goto do_verify_cleanup;
    }

    if (EVP_DigestVerifyUpdate(mdctx, msg, msglen) != 1)
    {
        dbg_perror("do_verify failed: EVP_DigestVerifyUpdate: %s", ERR_reason_error_string(ERR_get_error()));
        goto do_verify_cleanup;
    }

    result = EVP_DigestVerifyFinal(mdctx, sig, siglen);
    if (result == 0)
    {
        dbg_pinfo("do_verify: signature is invalid");
        result = 0;
    }
    else if (result == 1)
    {
        dbg_pinfo("do_verify: signature is valid");
        result = 1;
    }
    else
    {
        dbg_perror("do_verify failed: EVP_DigestVerifyFinal: %s", ERR_reason_error_string(ERR_get_error()));
        result = 12;
    }

do_verify_cleanup:
    if (mdctx) EVP_MD_CTX_free(mdctx);

    return result;
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
        goto read_key_cleanup;
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
        goto read_key_cleanup;
    }

    // ossl decoder promises to not change the data through pointer p
    const unsigned char* p = keybuf;
    size_t l = (size_t)keylen;

    if (!OSSL_DECODER_from_data(dctx, &p, &l))
    {
        dbg_perror("read_key failed: OSSL_DECODER_from_data");
        goto read_key_cleanup;
    }

    return_code = 0;

read_key_cleanup:
    if (dctx) OSSL_DECODER_CTX_free(dctx);
    if (keybuf) free(keybuf);

    return return_code;
}

static int compare_range(const void* a, const void* b)
{
    const struct range* ra = a;
    const struct range* rb = b;
    if (ra->off > rb->off) return 1;
    if (ra->off < rb->off) return -1;
    return 0;
}

// collect_exec_sections
// allocates an array of ranges that represent the sections
int collect_exec_sections(Elf* elf, struct range** out, size_t* out_count)
{
    size_t phnum;
    if (elf_getphdrnum(elf, &phnum) < 0) return -1;

    // collect executable segments (PF_X)
    struct range* segments = calloc(phnum, sizeof(*segments));
    if (!segments)
    {
        dbg_perror("collect_exec_sections failed: malloc for segments");
        return -1;
    }

    size_t segcnt = 0;
    for (size_t i = 0; i < phnum; ++i)
    {
        GElf_Phdr ph;
        if (!gelf_getphdr(elf, (int)i, &ph)) return -1;
        if (ph.p_type == PT_LOAD && (ph.p_flags & PF_X))
        {
            segments[segcnt++] = (struct range){ .off = ph.p_offset, .size = ph.p_filesz };
        }
    }

    dbg_pinfo("collect_exec_sections: found %zu executable segments", segcnt);

    // collect sections that fall within those segments
    size_t cap = 16, count = 0;
    struct range* sections = malloc(cap * sizeof(*sections));
    if (!sections)
    {
        dbg_perror("collect_exec_sections failed: malloc for sections");
        free(segments);
        return -1;
    }

    Elf_Scn* scn = NULL;
    while ((scn = elf_nextscn(elf, scn)) != NULL)
    {
        GElf_Shdr sh;
        if (!gelf_getshdr(scn, &sh))
        {
            dbg_perror("collect_exec_sections failed: gelf_getshdr: %s", elf_errmsg(-1));
            free(sections);
            free(segments);
            return -1;
        }
        if (!sh.sh_size) continue;
        if (!(sh.sh_flags & SHF_EXECINSTR)) continue;

        off_t s_off = sh.sh_offset;
        size_t s_size = sh.sh_size;

        for (size_t j = 0; j < segcnt; ++j)
        {
            dbg_pinfo("  seg[%zu] range %zu..%zu  section %zu..%zu flags=0x%llx",
                j,
                (size_t)segments[j].off,
                (size_t)(segments[j].off + segments[j].size),
                (size_t)s_off,
                (size_t)(s_off + s_size),
                (unsigned long long)sh.sh_flags);

            size_t strndx;
            elf_getshdrstrndx(elf, &strndx);
            const char* name = elf_strptr(elf, strndx, sh.sh_name);

            dbg_pinfo("sec %-12s off=%zu size=%zu flags=0x%llx",
                name ? name : "<?>",
                (size_t)s_off, (size_t)s_size,
                (unsigned long long)sh.sh_flags);

            if (s_off >= segments[j].off && (s_off + s_size) <= (segments[j].off + segments[j].size))
            {
                dbg_pinfo("collect_exec_sections: found section %zu at offset %zu", j, s_off);
                if (count == cap)
                {
                    cap *= 2;
                    struct range* tmp = realloc(sections, cap * sizeof * sections);
                    if (!tmp) { free(sections); free(segments); return -1; }
                    sections = tmp;
                }
                sections[count].off = s_off;
                sections[count].size = s_size;
                count++;
                break;
            }
        }
    }

    free(segments);

    // if no sections were found, free the allocated memory and return -1
    if (count == 0)
    {
        dbg_perror("collect_exec_sections failed: no executable sections found");
        free(sections);
        return -1;
    }
    // sort by file offset for deterministic hashing
    qsort(sections, count, sizeof(*sections), compare_range);

    *out = sections;
    *out_count = count;
    return 0;
}

int dump_sections(Elf* e, unsigned char** msg, size_t* msglen, struct range* sections, size_t sections_count)
{
    size_t tmp_msglen = 0;
    unsigned char* tmp_msg = NULL;

    for (size_t i = 0; i < sections_count; ++i)
    {
        tmp_msglen += sections[i].size;
    }

    tmp_msg = malloc(tmp_msglen);
    if (!tmp_msg)
    {
        dbg_perror("dump sections failed: malloc for msg failed");
        free(tmp_msg);
        return -1;
    }

    size_t offset = 0;
    for (size_t i = 0; i < sections_count; ++i)
    {
        Elf_Scn* scn = gelf_offscn(e, sections[i].off);
        if (!scn)
        {
            dbg_perror("dump sections failed: elf_getscn failed: %s", elf_errmsg(-1));
            free(tmp_msg);
            return -1;
        }
        Elf_Data* data = elf_getdata(scn, NULL);
        if (!data)
        {
            dbg_perror("dump sections failed: elf_getdata failed: %s", elf_errmsg(-1));
            free(tmp_msg);
            return -1;
        }
        memcpy(tmp_msg + offset, data->d_buf, sections[i].size);
        offset += sections[i].size;
    }

    *msglen = tmp_msglen;
    *msg = tmp_msg;

    return 0;
}

// sign_elf
// return 0 on success
// return 10+ on error
int sign_elf(const char* elf_file, const char* key_file)
{
    Elf* elf = NULL;

    // buffer of the message to sign
    unsigned char* msg = NULL;

    // signing key
    EVP_PKEY* signing_key = NULL;

    // signature buffer
    unsigned char* sig_buf = NULL;
    size_t sig_buf_size = 0;

    // sections to sign
    struct range* sections = NULL;

    int fd = -1;
    int tmp = 0;
    int status_code = 10; // elf file sign general error

    if ((fd = open(elf_file, O_RDONLY)) < 0)
    {
        dbg_perror("signing failed: open failed: %s", elf_file);
        goto sign_elf_cleanup;
    }

    // read key
    if ((tmp = read_key(key_file, 1, &signing_key)) != 0)
    {
        dbg_perror("signing failed: read_key failed: code %d, reading %s", tmp, key_file);
        goto sign_elf_cleanup;
    }

    // singing_key is initialized with the private key here

    elf = elf_begin(fd, ELF_C_RDWR, NULL);

    // collect executable sections
    size_t sections_count = 0;
    if (collect_exec_sections(elf, &sections, &sections_count) != 0)
    {
        dbg_perror("signing failed: collect_exec_sections failed");
        goto sign_elf_cleanup;
    }

    dbg_pinfo("executable sections collected");


    size_t msglen = 0;
    // dump sections into a contiguous buffer
    if (dump_sections(elf, &msg, &msglen, sections, sections_count) != 0)
    {
        dbg_perror("signing failed: dump_sections failed");
        goto sign_elf_cleanup;
    }

    dbg_pinfo("sections dumped into contiguous buffer");

    // print sha256 of the message
    if (debug)
    {
        unsigned char digest[32];
        unsigned int digest_len = 0;
        if (hash_buffer_sha256(msg, msglen, digest, &digest_len) == 0)
        {
            printf("[  INFO ] SHA-256: ");
            for (unsigned int i = 0; i < digest_len; ++i)
            {
                printf("%02x", digest[i]);
            }
            printf("\n");
        }
    }

    // calculate signature
    // do_sign will allocate sig_buf and set sig_buf_size to the size of the signature
    if (do_sign(msg, msglen, signing_key, &sig_buf, &sig_buf_size) != 0)
    {
        dbg_perror("signing failed: do_sign failed");
        goto sign_elf_cleanup;
    }

    dbg_pinfo("signature calculated");

    if (add_section(elf_file, sig_buf, sig_buf_size) != 0)
    {
        dbg_perror("signing failed: add_section failed");
        goto sign_elf_cleanup;
    }

    dbg_pinfo("signature written to .signature section");
    status_code = 0;

sign_elf_cleanup:
    if (signing_key) EVP_PKEY_free(signing_key);
    if (sig_buf) OPENSSL_free(sig_buf);
    if (elf) elf_end(elf);
    if (msg) free(msg);
    if (sections) free(sections);
    if (fd != -1) close(fd);
    return status_code;
}

// verify_elf
// return 0 on valid signature
// return 1 on invalid signature
// return 2 on no signature section
// return 10+ on error
int verify_elf(const char* elf_file, const char* key_file)
{
    Elf* elf = NULL;

    // buffer of the message to sign
    unsigned char* msg = NULL;

    // signing key
    EVP_PKEY* verifying_key = NULL;

    // signature buffer
    unsigned char* sig_buf = NULL;
    size_t sig_buf_size = 0;

    // sections to sign
    struct range* sections = NULL;

    int fd = -1;
    int tmp = 0;
    int status_code = 10; // elf file verify general error

    if ((fd = open(elf_file, O_RDONLY)) < 0)
    {
        dbg_perror("verifying failed: open failed: %s", elf_file);
        goto verify_cleanup;
    }

    // check if the file is signed
    elf = elf_begin(fd, ELF_C_RDWR, NULL);
    if (!elf)
    {
        dbg_perror("verifying failed: elf_begin failed: %s", elf_errmsg(-1));
        goto verify_cleanup;
    }

    // find the signature section
    Elf_Scn* sig_scn = find_section_by_name(elf, SIGNATURE_SECTION_NAME);
    if (!sig_scn)
    {
        dbg_perror("verifying failed: no .signature section found");
        status_code = 2;
        goto verify_cleanup;
    }

    // read the signature section
    Elf_Data* sig_data = elf_getdata(sig_scn, NULL);
    if (sig_data->d_size == 0)
    {
        dbg_perror("verifying failed: empty .signature section");
        goto verify_cleanup;
    }
    if (sig_data->d_buf == NULL)
    {
        dbg_perror("verifying failed: no data in .signature section");
        goto verify_cleanup;
    }

    sig_buf = sig_data->d_buf;
    sig_buf_size = sig_data->d_size;

    // read key
    if ((tmp = read_key(key_file, 0, &verifying_key)) != 0)
    {
        dbg_perror("verifying failed: read_key failed: code %d, reading %s", tmp, key_file);
        goto verify_cleanup;
    }

    // verifying_key is initialized with the private key here

    // collect executable sections
    size_t sections_count = 0;
    if (collect_exec_sections(elf, &sections, &sections_count) != 0)
    {
        dbg_perror("verifying failed: collect_exec_sections failed");
        goto verify_cleanup;
    }

    dbg_pinfo("executable sections collected");

    size_t msglen = 0;
    // dump sections into a contiguous buffer
    if (dump_sections(elf, &msg, &msglen, sections, sections_count) != 0)
    {
        dbg_perror("verifying failed: dump_sections failed");
        goto verify_cleanup;
    }

    dbg_pinfo("sections dumped into contiguous buffer");

    // print sha256 of the message
    if (debug)
    {
        unsigned char digest[32];
        unsigned int digest_len = 0;
        if (hash_buffer_sha256(msg, msglen, digest, &digest_len) == 0)
        {
            printf("[  INFO ] SHA-256: ");
            for (unsigned int i = 0; i < digest_len; ++i)
            {
                printf("%02x", digest[i]);
            }
            printf("\n");
        }
    }

    // verify signature
    // do_verify will allocate sig_buf and set sig_buf_size to the size of the signature
    if ((tmp = do_verify(msg, msglen, verifying_key, sig_buf, sig_buf_size)) == 2)
    {
        dbg_perror("verifying failed: do_verify failed");
        status_code = 11;
        goto verify_cleanup;
    }

    if (tmp == 0)
    {
        dbg_pinfo("verifying succeeded: signature is invalid");
        status_code = 1;
        goto verify_cleanup;
    }
    else if (tmp == 1)
    {
        dbg_pinfo("verifying succeeded: signature is valid");
        status_code = 0;
        goto verify_cleanup;
    }
    else
    {
        dbg_perror("verifying failed: do_verify failed: code %d", tmp);
        status_code = 12;
        goto verify_cleanup;
    }

verify_cleanup:
    if (verifying_key) EVP_PKEY_free(verifying_key);
    if (elf) elf_end(elf);
    if (msg) free(msg);
    if (sections) free(sections);
    if (fd != -1) close(fd);
    return status_code;
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

    if (argc < 5)
    {
        fprintf(stderr, "usage: %s sign|verify -e <executable> -k <key>\n", argv[0]);
        return -1;
    }

    if (strcmp(argv[1], "sign") == 0)
    {
        m = SIGN;
    }
    else if (strcmp(argv[1], "verify") == 0)
    {
        m = VERIFY;
    }

    for (int i = 2; i < argc; i += 2)
    {
        if (strcmp(argv[i], "-e") == 0)
        {
            arg_file = argv[i + 1];
        }
        else if (strcmp(argv[i], "-k") == 0)
        {
            arg_key = argv[i + 1];
        }
    }

    int fd = -1;
    Elf* e_in = NULL;
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
    if ((e_in = elf_begin(fd, ELF_C_READ, NULL)) == NULL)
    {
        dbg_perror("elf_begin failed: %s", elf_errmsg(-1));
        goto err;
    }
    if ((ek = elf_kind(e_in)) != ELF_K_ELF)
    {
        dbg_perror("elf_kind returned non-executable: %d", ek);
        goto err;
    }
    if (elf_end(e_in) != 0)
    {
        dbg_perror("elf_end failed: %s", elf_errmsg(-1));
        goto err;
    }
    if (close(fd) < 0)
    {
        // leave on closing anomalies
        dbg_perror("close failed: %s", arg_file);
        goto err;
    }

    int exit_code = 1;
    int tmp = 0;

    if (m == SIGN)
    {
        tmp = sign_elf(arg_file, arg_key);
        if (tmp == 0)
        {
            dbg_pinfo("signing succeeded");
            printf(MSG_OK);
            exit_code = 0;
        }
        else
        {
            dbg_perror("signing failed: sign_elf failed: code %d", tmp);
            exit_code = 1;
            goto err;
        }

    }
    else if (m == VERIFY)
    {
        tmp = verify_elf(arg_file, arg_key);
        if (tmp == 0)
        {
            dbg_pinfo("verifying succeeded");
            printf(MSG_OK);
            exit_code = 0;
        }
        else if (tmp == 1)
        {
            dbg_pinfo("verifying succeeded: signature is invalid");
            printf(MSG_NOT_OK);
            exit_code = 1;
        }
        else if (tmp == 2)
        {
            dbg_pinfo("verifying succeeded: no .signature section");
            printf(MSG_NOT_SIGNED);
            exit_code = 2;
        }
        else
        {
            dbg_perror("verifying failed: verify_elf failed: code %d", tmp);
            exit_code = 1;
            goto err;
        }
    }
    else
    {
        fprintf(stderr, "unknown mode: %s\n", argv[1]);
        exit_code = 2;
    }

    exit_code = 0;

err:
    dbg_pinfo("exiting signtool");
    if (fd != -1) close(fd);
    return exit_code;
}