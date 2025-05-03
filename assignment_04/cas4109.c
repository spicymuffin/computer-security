#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cas4109.h"

int add_section(char *infilepath, unsigned char *buf, size_t buf_len) {
    int ret = 0;
    char *outfilepath = NULL;
    FILE *fp = NULL;

    if (access(infilepath, F_OK) != 0) {
        ret = -4;
        goto clean;
    }

    if (buf == NULL) {
        ret = -2;
        goto clean;
    }

    if (buf_len == 0) {
        ret = -3;
        goto clean;
    }

    char *ext = "-signed";
    outfilepath = malloc(strlen(infilepath) + strlen(ext) + 1);
    strcpy(outfilepath, infilepath);
    strcat(outfilepath, ext);

    fp = fopen("/tmp/signtool-sig", "w");
    if (fp == NULL) {
        ret = -5;
        goto clean;
    }
    fwrite(buf, buf_len, 1, fp);
    fflush(fp);
    fclose(fp);
    fp = NULL;

    ret = execlp("objcopy", "objcopy", "--add-section", ".signature=/tmp/signtool-sig", "--set-section-flags", ".signature=noload,readonly", infilepath, outfilepath, (char *)NULL);

clean:
    if (outfilepath) free(outfilepath);
    if (fp) fclose(fp);

    return ret;
}
