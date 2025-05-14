#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdarg.h>

#include "dbgutil.h"

int debug = 0;

void dbg_perror(const char* format, ...)
{
    if (debug == 0) return;
    va_list args;
    fprintf(stderr, "[ ERROR ] ");
    va_start(args, format);
    vfprintf(stderr, format, args);
    va_end(args);
    fprintf(stderr, "\n");
}

void dbg_pinfo(const char* format, ...)
{
    if (debug == 0) return;
    va_list args;
    fprintf(stderr, "[  INFO ] ");
    va_start(args, format);
    vfprintf(stderr, format, args);
    va_end(args);
    fprintf(stderr, "\n");
}
