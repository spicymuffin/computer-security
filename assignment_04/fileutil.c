#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>

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

long read_file_fd(int fd, unsigned char** buffer)
{
    struct stat st;
    long filelen;

    // Get file size
    if (fstat(fd, &st) != 0)
    {
        dbg_perror("fstat failed: %s", strerror(errno));
        return -1;
    }

    filelen = st.st_size;

    // Allocate buffer
    *buffer = (unsigned char*)malloc((size_t)filelen);
    if (*buffer == NULL)
    {
        dbg_perror("malloc failed: %s", strerror(errno));
        return -1;
    }

    // Read file content
    ssize_t total_read = 0;
    while (total_read < filelen)
    {
        ssize_t bytes = read(fd, *buffer + total_read, filelen - total_read);
        if (bytes < 0)
        {
            dbg_perror("read failed: %s", strerror(errno));
            free(*buffer);
            return -1;
        }
        if (bytes == 0)
        {
            break;  // EOF
        }
        total_read += bytes;
    }

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

int copy_file(const char* src, const char* dst)
{
    int in_fd = open(src, O_RDONLY);
    if (in_fd < 0)
    {
        dbg_perror("copy_file: open src failed: %s", src);
        return -1;
    }

    int out_fd = open(dst, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (out_fd < 0)
    {
        dbg_perror("copy_file: open dst failed: %s", dst);
        close(in_fd);
        return -1;
    }

    char buf[4096];
    ssize_t bytes_read, bytes_written;

    while ((bytes_read = read(in_fd, buf, sizeof(buf))) > 0)
    {
        bytes_written = write(out_fd, buf, bytes_read);
        if (bytes_written != bytes_read)
        {
            dbg_perror("copy_file: write failed");
            close(in_fd);
            close(out_fd);
            return -1;
        }
    }

    if (bytes_read < 0)
    {
        dbg_perror("copy_file: read failed");
    }

    close(in_fd);
    close(out_fd);
    return (bytes_read < 0) ? -1 : 0;
}
