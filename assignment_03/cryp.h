#ifndef CRYP_H
#define CRYP_H

#define ERROR_MSG "ERROR\n"
#define HMAC_FAIL_MSG "VERIFICATION FAILURE\n"

#define LIT_ENCRYPT_MODE_ARG "enc"
#define LIT_DECRYPT_MODE_ARG "dec"

#define IV_LEN 16        // for AES-CTR
#define AES_KEY_LEN 32   // for AES-256
#define TAG_LEN 32       // output size of SHA256

enum mode
{
    ENCRYPT = 0,
    DECRYPT = 1
};

#endif
