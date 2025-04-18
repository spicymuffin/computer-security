#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <openssl/evp.h>

#include "cryp.h"

int main(int argc, char *argv[]) {
    if (argc < 10) {
        printf(ERROR_MSG);
        return 2;
    }

    
}