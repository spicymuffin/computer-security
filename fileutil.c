#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "dbgutil.h"
#include "fileutil.h"

long read_file(const char* filename, unsigned char** buffer)
{
    FILE* fileptr;
    long filelen;

    fileptr = fopen(filename, "rb");
    if (fileptr == NULL)
    {
        dbg_perror("%s: failed to open file", filename);
        return -1;
    }
    if (fseek(fileptr, 0, SEEK_END) != 0)
    {
        dbg_perror("%s: failed to seek to end of file", filename);
        fclose(fileptr);
        return -1;
    }
    filelen = ftell(fileptr);
    if (filelen == -1)
    {
        dbg_perror("%s: failed to get file length", filename);
        fclose(fileptr);
        return -1;
    }
    rewind(fileptr);
    *buffer = (unsigned char*)malloc(((size_t)filelen) * sizeof(char));
    if (*buffer == NULL)
    {
        dbg_perror("%s: failed to allocate memory for file buffer", filename);
        fclose(fileptr);
        return -1;
    }
    // swapped n and size bc we inferred the filelen with ftell
    if (fread(*buffer, filelen, 1, fileptr) != 1)
    {
        dbg_perror("%s: failed to read file:", filename);
        free(*buffer);
        fclose(fileptr);
        return -1;
    }
    fclose(fileptr);

    return filelen;
}

long read_file_max_n_chars(const char* filename, unsigned char* buffer, size_t n)
{
    FILE* fileptr;

    fileptr = fopen(filename, "rb");
    if (fileptr == NULL)
    {
        dbg_perror("%s: failed to open file", filename);
        return -1;
    }
    size_t bytes_read = fread(buffer, 1, n, fileptr);
    if (bytes_read < n && ferror(fileptr))
    {
        dbg_perror("%s: failed to read file", filename);
        fclose(fileptr);
        return -1;
    }
    fclose(fileptr);

    return bytes_read;
}

int write_file(const char* filename, const unsigned char* buffer, size_t length)
{
    FILE* fileptr;

    fileptr = fopen(filename, "wb");
    if (fileptr == NULL)
    {
        dbg_perror("%s: failed to open file for writing", filename);
        return -1;
    }
    if (fwrite(buffer, length, 1, fileptr) != 1)
    {
        dbg_perror("%s: failed to write to file", filename);
        fclose(fileptr);
        return -1;
    }
    fclose(fileptr);

    return 0;
}
