#ifndef FILEUTIL_H
#define FILEUTIL_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

long read_file(const char* filename, unsigned char** buffer);
long read_file_fd(int fd, unsigned char** buffer);
long read_file_max_n_chars(const char* filename, unsigned char* buffer, size_t n);
int write_file(const char* filename, const unsigned char* buffer, size_t length);
int copy_file(const char *src, const char *dst);

#endif
