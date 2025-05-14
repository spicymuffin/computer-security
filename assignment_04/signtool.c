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

// verifies that the signature sig of length siglen
// matches the msg of length msglen using the public verify_key
// returns 1 if the signature is valid, 0 if invalid, -1 on error
int do_verify(const unsigned char* msg, size_t msglen, EVP_PKEY* verify_key, const unsigned char* sig, size_t siglen)
{
    int result = -1;
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
    if (result == 1)
    {
        result = 1;
    }
    else if (result == 0)
    {
        dbg_perror("do_verify failed: signature verification failed (invalid signature)");
        result = 0;
    }
    else
    {
        dbg_perror("do_verify failed: EVP_DigestVerifyFinal: %s", ERR_reason_error_string(ERR_get_error()));
        result = -1;
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

int add_scn_name_to_shstrtab(Elf* e_copy, const char* scn_name, size_t* unsigned_shstrtab_size)
{
    // update the shstrtab
    size_t shstrtab_index = 0;

    // get the section header string table index
    if (elf_getshdrstrndx(e_copy, &shstrtab_index) != 0)
    {
        dbg_perror("signing failed: elf_getshstrndx failed: %s", elf_errmsg(-1));
        return -1;
    }

    // get the section header string table
    Elf_Scn* shstrtab_scn = elf_getscn(e_copy, shstrtab_index);
    if (shstrtab_scn == NULL)
    {
        dbg_perror("signing failed: elf_getscn failed: %s", elf_errmsg(-1));
        return -1;
    }

    // get the section header string table data
    Elf_Data* shstrtab_data = elf_getdata(shstrtab_scn, NULL);
    if (shstrtab_data == NULL)
    {
        dbg_perror("signing failed: elf_getdata failed: %s", elf_errmsg(-1));
        return -1;
    }

    // get the size of the section header string table
    *unsigned_shstrtab_size = shstrtab_data->d_size;

    // set the name of the section header string table
    size_t signature_scn_name_len = strlen(scn_name) + 1;

    Elf_Data* signed_shstrtab_data = elf_newdata(shstrtab_scn);
    if (signed_shstrtab_data == NULL)
    {
        dbg_perror("signing failed: elf_newdata failed: %s", elf_errmsg(-1));
        return -1;
    }

    // update the section header string table
    signed_shstrtab_data->d_align = 1;
    signed_shstrtab_data->d_buf = (void*)scn_name;
    signed_shstrtab_data->d_size = signature_scn_name_len;
    signed_shstrtab_data->d_type = ELF_T_BYTE;
    signed_shstrtab_data->d_version = EV_CURRENT;

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

static off_t
get_next_free_offset(Elf* elf)
{
    Elf_Scn* scn = NULL;
    GElf_Shdr   sh;
    off_t       max_end = 0;

    while ((scn = elf_nextscn(elf, scn)) != NULL)
    {
        if (gelf_getshdr(scn, &sh) != &sh)
            continue;
        off_t end = sh.sh_offset + sh.sh_size;
        if (end > max_end)
            max_end = end;
    }
    return max_end;
}

int create_signed_elf(const char* elf_file, const char* key_file)
{
    // copied file
    char* copy_file_path = NULL;
    Elf* e_copy = NULL;
    int copy_fd = -1;

    // buffer of the message to sign
    unsigned char* msg = NULL;

    // signing key
    EVP_PKEY* signing_key = NULL;

    // signature buffer
    unsigned char* sig_buf = NULL;
    size_t sig_buf_size = 0;

    // buffer for the zeroed section
    unsigned char* zero_buf = NULL;

    struct range* sections = NULL;

    int tmp = 0;

    int status_code = 10; // elf file sign general error

    // create a copy of the file we are going to sign
    // this is the file we will be signing
    copy_file_path = calloc(1, strlen(elf_file) + strlen(SIGNATURE_POSTFIX) + 1);
    copy_file_path = strcpy(copy_file_path, elf_file);
    copy_file_path = strcat(copy_file_path, SIGNATURE_POSTFIX);

    if ((copy_file(elf_file, copy_file_path) != 0))
    {
        dbg_perror("signing failed: copy_file failed");
        goto create_signed_elf_cleanup;
    }

    if ((copy_fd = open(copy_file_path, O_RDWR, 0)) < 0)
    {
        dbg_perror("signing failed: open failed: %s", copy_file_path);
        goto create_signed_elf_cleanup;
    }

    // read key
    if ((tmp = read_key(key_file, 1, &signing_key)) != 0)
    {
        dbg_perror("signing failed: read_key failed: code %d, reading %s", tmp, key_file);
        status_code = 11; // read key failed
        goto create_signed_elf_cleanup;
    }

    // singing_key is initialized with the private key here

    e_copy = elf_begin(copy_fd, ELF_C_RDWR, NULL);

    elf_flagelf(e_copy, ELF_C_SET, ELF_F_LAYOUT);

    // now we need to start actually signing the file
    // first check if the section already exists
    Elf_Scn* sig_scn;
    size_t sig_size = SIGNATURE_LEN;
    sig_scn = find_section_by_name(e_copy, SIGNATURE_SECTION_NAME);

    if (sig_scn == NULL)
    {
        sig_scn = elf_newscn(e_copy);
        if (sig_scn == NULL)
        {
            dbg_perror("signing failed: elf_newscn failed: %s", elf_errmsg(-1));
            goto create_signed_elf_cleanup;
        }
    }

    // empty buf that will be used to create/populate the section
    zero_buf = calloc(1, sig_size);
    if (zero_buf == NULL)
    {
        dbg_perror("signing failed: calloc for zero buf failed");
        goto create_signed_elf_cleanup;
    }

    Elf_Data* sig_data = elf_getdata(sig_scn, NULL);

    if (sig_data == NULL || sig_data->d_size == 0)
    {
        if (sig_data == NULL)
        {
            // we created/loaded an in memory shdr, its data is non existent
            sig_data = elf_newdata(sig_scn);
            if (sig_data == NULL)
            {
                dbg_perror("signing failed: elf_newdata failed: %s", elf_errmsg(-1));
                goto create_signed_elf_cleanup;
            }
        }

        // section loaded/created. anyways set its parameters to what we need
        sig_data->d_align = 1;              // alignment is 1 (we don't care)
        sig_data->d_buf = zero_buf;         // data buffer
        sig_data->d_size = sig_size;        // reserve space for signature
        sig_data->d_type = ELF_T_BYTE;      // type is unsigned char
        sig_data->d_version = EV_CURRENT;   // version is current
    }

    // add the section name to the shstrtab
    size_t unsigned_shstrtab_size = 0;
    if (add_scn_name_to_shstrtab(e_copy, SIGNATURE_SECTION_NAME, &unsigned_shstrtab_size) != 0)
    {
        dbg_perror("signing failed: add_scn_name_to_shstrtab failed");
        goto create_signed_elf_cleanup;
    }

    // update the section header
    GElf_Shdr shdr;
    gelf_getshdr(sig_scn, &shdr);
    shdr.sh_name = unsigned_shstrtab_size; // offset in the shstrtab = size of the original shstrtab
    shdr.sh_type = SHT_PROGBITS;
    shdr.sh_flags = 0; // no need to load this section when runnning so we set it to 0
    shdr.sh_addralign = 1;
    shdr.sh_offset = get_next_free_offset(e_copy); // offset in the file
    shdr.sh_size = sig_size; // size of the section is the size of the signature
    gelf_update_shdr(sig_scn, &shdr);

    // sync the updated elf file with disk
    if (elf_update(e_copy, ELF_C_WRITE) < 0)
    {
        dbg_perror("signing failed: elf_update failed: %s", elf_errmsg(-1));
        goto create_signed_elf_cleanup;
    }

    dbg_pinfo("-signed executable file created and .sig section added");

    // elf file modified, signature section+data allocated
    // still general error
    status_code = 20;

    // collect executable sections
    size_t sections_count = 0;
    if (collect_exec_sections(e_copy, &sections, &sections_count) != 0)
    {
        dbg_perror("signing failed: collect_exec_sections failed");
        goto create_signed_elf_cleanup;
    }

    dbg_pinfo("executable sections collected");


    size_t msglen = 0;
    // dump sections into a contiguous buffer
    if (dump_sections(e_copy, &msg, &msglen, sections, sections_count) != 0)
    {
        dbg_perror("signing failed: dump_sections failed");
        goto create_signed_elf_cleanup;
    }

    dbg_pinfo("sections dumped into contiguous buffer");

    // calculate signature
    // do_sign will allocate sig_buf and set sig_buf_size to the size of the signature
    if (do_sign(msg, msglen, signing_key, &sig_buf, &sig_buf_size) != 0)
    {
        dbg_perror("signing failed: do_sign failed");
        goto create_signed_elf_cleanup;
    }

    dbg_pinfo("signature calculated");

    // assert that the signature is the same size as the section
    if (sig_buf_size != SIGNATURE_LEN)
    {
        dbg_perror("signing failed: signature size is not %d", SIGNATURE_LEN);
        goto create_signed_elf_cleanup;
    }

    // write signature to .signature section
    // note: size of the signature is *unmodified*
    sig_data->d_buf = sig_buf; // signature buffer

    // update the elf file with the signature
    if (elf_update(e_copy, ELF_C_WRITE) < 0)
    {
        dbg_perror("signing failed: elf_update failed: %s", elf_errmsg(-1));
        goto create_signed_elf_cleanup;
    }

    dbg_pinfo("signature written to .signature section");
    status_code = 0;

create_signed_elf_cleanup:
    if (signing_key) EVP_PKEY_free(signing_key);
    if (copy_file_path) free(copy_file_path);
    if (sig_buf) OPENSSL_free(sig_buf);
    if (zero_buf) free(zero_buf);
    if (e_copy) elf_end(e_copy);
    if (msg) free(msg);
    if (sections) free(sections);
    if (copy_fd != -1) close(copy_fd);
    return status_code;
}

int verify_elf(const char* elf_file, const char* key_file)
{
    EVP_PKEY* verifying_key = NULL;
    Elf* e_ro = NULL;
    unsigned char* file_img = NULL;
    int result = -1;
    int fd = -1;
    int status_code = 60; // elf file verify general error

    // load public key
    if (read_key(key_file, 0, &verifying_key) != 0)
    {
        dbg_perror("verifying failed: read_key");
        goto verify_cleanup;
    }

    // open executable read-only, map with libelf
    if ((fd = open(key_file, O_RDONLY)) < 0)
    {
        dbg_perror("verifying failed: open");
        goto verify_cleanup;
    }
    if ((e_ro = elf_begin(fd, ELF_C_READ, NULL)) == NULL)
    {
        dbg_perror("verifying failed: elf_begin: %s", elf_errmsg(-1));
        goto verify_cleanup;
    }
    if (elf_kind(e_ro) != ELF_K_ELF)
    {
        dbg_perror("verifying failed: not an ELF file");
        goto verify_cleanup;
    }

    // check signature section
    Elf_Scn* sig_scn = find_section_by_name(e_ro, SIGNATURE_SECTION_NAME);
    if (!sig_scn)
    {
        dbg_pinfo("verifying succeeded: no .signature section");
        status_code = 61;
        goto verify_cleanup;
    }

    GElf_Shdr shdr;
    if (!gelf_getshdr(sig_scn, &shdr))
    {
        dbg_perror("verifying failed: gelf_getshdr: %s", elf_errmsg(-1));
        goto verify_cleanup;
    }

    // verify signature length
    if (shdr.sh_size != SIGNATURE_LEN)
    {
        dbg_perror("verifying succeeded: signature size mismatch "
            "(found %zu, expected %d)", (size_t)shdr.sh_size, SIGNATURE_LEN);
        status_code = 62;
        goto verify_cleanup;
    }

    // copy signature payload into local buffer
    unsigned char signature_buf[SIGNATURE_LEN];
    if (pread(fd, signature_buf, SIGNATURE_LEN, shdr.sh_offset) != SIGNATURE_LEN)
    {
        dbg_perror("verifying failed: pread signature");
        goto verify_cleanup;
    }
    dbg_pinfo("valid signature read");

    // read the whole file into memory
    off_t fsize = lseek(fd, 0, SEEK_END);
    if (fsize < 0)
    {
        dbg_perror("verifying failed: lseek");
        goto verify_cleanup;
    }

    file_img = malloc((size_t)fsize);
    if (!file_img)
    {
        dbg_perror("verifying failed: img malloc");
        goto verify_cleanup;
    }

    lseek(fd, 0, SEEK_SET);
    if (read(fd, file_img, (size_t)fsize) != fsize)
    {
        dbg_perror("verifying failed: read file");
        goto verify_cleanup;
    }
    dbg_pinfo("file image loaded");

    // zero the signature payload *in memory* only
    memset(file_img + shdr.sh_offset, 0, shdr.sh_size);
    dbg_pinfo(".sig section zeroed in memory");

    // verify the signature
    result = do_verify(file_img, (size_t)fsize, verifying_key, signature_buf, SIGNATURE_LEN);

    if (result == 1)
    {
        dbg_pinfo("verifying succeeded: signature is valid");
        printf(MSG_OK);
        status_code = 0; // status code 0 means signature is valid
    }
    else if (result == 0)
    {
        dbg_pinfo("verifying succeeded: signature is invalid");
        printf(MSG_NOT_OK);
        status_code = 1; // status code 1 means signature is invalid or signature section corrupted
    }
    else
    {
        dbg_perror("verifying failed: do_verify");
    }

verify_cleanup:
    if (e_ro)          elf_end(e_ro);
    if (file_img)      free(file_img);
    if (verifying_key) EVP_PKEY_free(verifying_key);
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
    debug = 1;

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
        tmp = create_signed_elf(arg_file, arg_key);
        if (tmp == 0)
        {
            dbg_pinfo("signing succeeded");
            printf(MSG_OK);
            exit_code = 0;
        }
        else
        {
            dbg_perror("signing failed: create_signed_elf failed: code %d", tmp);
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