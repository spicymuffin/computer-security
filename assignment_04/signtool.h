#ifndef SIGNTOOL_H
#define SIGNTOOL_H

#define MSG_OK "OK\n"
#define MSG_NOT_OK "NOT_OK\n"
#define MSG_NOT_SIGNED "NOT_SIGNED\n"

#define SIGNATURE_LEN 256
#define SIGNATURE_SECTION_NAME ".signature"
#define SIGNATURE_POSTFIX "-signed"

#define TMP_FILE_PATH "/tmp/signtool-tmp-file-XXXXXX"

enum mode
{
    SIGN = 0,
    VERIFY = 1,
};

#endif