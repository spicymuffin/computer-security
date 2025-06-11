#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>          // for open()
#include <unistd.h>         // for close(), usleep()
#include <sys/mman.h>       // for mmap(), munmap(), mincore()
#include <sys/stat.h>       // for fstat()
#include <time.h>           // for clock_gettime()
#include <string.h>         // for strstr()
#include <sys/time.h>       // for gettimeofday()
#include "tokenizer.h"
#ifndef MADV_DONTNEED
#define MADV_DONTNEED 4     // for madvise()
#endif
#ifndef __USE_POSIX199309
#define __USE_POSIX199309 1 // for monotonic clock
#endif
#ifndef POSIX_FADV_DONTNEED
#define POSIX_FADV_DONTNEED	4
#endif

#define PROFILING 0

#if PROFILING
static struct timespec start, end;
static inline void start_timer()
{
    clock_gettime(CLOCK_MONOTONIC, &start);
}

static inline double end_timer()
{
    clock_gettime(CLOCK_MONOTONIC, &end);
    return (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;
}
#endif

static char EVT_PATH[] = "embedding_layer.bin";      // embedding vector table path
static char TOKENIZER_PATH[] = "tokenizer.bin";      // tokenizer path
static int PAGE_SIZE = 4096;                         // pagesize
static int VOCAB_SIZE = 32000;                       // vocabulary size in tokens (not semantic tokens)
static char SERVER_NAME[] = "llama2-server";         // server name to find the PID

static int FILE_LOOKUP_REFRESH_INTERVAL = 10000; // time to sleep in microseconds when searching for the file
static int PID_LOOKUP_REFRESH_INTERVAL = 0;      // time to sleep in microseconds when searching for the PID
static int MMAP_LOOKUP_REFRESH_INTERVAL = 10000; // time to sleep in microseconds when searching for the mmap

static double exit_timeout = 2.75; // time that needs to elapse with no new tokens before the program exits

#define PRINT_FILE_LOOKUP_STATUS 0
#define PRINT_PID_LOOKUP_STATUS 0
#define PRINT_MMAP_LOOKUP_STATUS 0

#define TRACE_TO_STDERR 0

int find_pid_by_name(const char* process_name)
{
    char command[256];
    sprintf(command, "pgrep %s", process_name);
    FILE* fp = popen(command, "r");
    if (!fp) return -1;

    int pid = -1;
    fscanf(fp, "%d", &pid);
    pclose(fp);
    return pid;
}

int is_file_mapped(int pid, const char* filename)
{
    if (pid <= 0) return 0;

    char maps_path[256];
    sprintf(maps_path, "/proc/%d/maps", pid);

    FILE* maps_file = fopen(maps_path, "r");
    if (!maps_file) return 0;

    char line[512];
    int found = 0;
    while (fgets(line, sizeof(line), maps_file))
    {
        if (strstr(line, filename))
        {
            found = 1;
            break;
        }
    }

    fclose(maps_file);
    return found;
}

double now_seconds()
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec + tv.tv_usec / 1e6;
}

int main(int argc, char* argv[])
{
    // build the tokenizer
    Tokenizer tokenizer;
    build_tokenizer(&tokenizer, TOKENIZER_PATH, VOCAB_SIZE);
    int evt_fd = -1;
    while (evt_fd == -1)
    {
        evt_fd = open(EVT_PATH, O_RDONLY);
        usleep(FILE_LOOKUP_REFRESH_INTERVAL);
    }


    int pid = -1;
    while (pid == -1)
    {
        pid = find_pid_by_name(SERVER_NAME);

        if (pid != -1)
        {
            #if PRINT_PID_LOOKUP_STATUS
            fprintf(stderr, "found PID of %s: %d\n", SERVER_NAME, pid);
            #endif
            break;
        }
        else
        {
            #if PRINT_PID_LOOKUP_STATUS
            fprintf(stderr, "PID of %s not found, retrying...\n", SERVER_NAME);
            #endif
            usleep(PID_LOOKUP_REFRESH_INTERVAL);
        }
    }


    int mmap_found = 0;
    while (!mmap_found)
    {
        mmap_found = is_file_mapped(pid, EVT_PATH);
        if (mmap_found)
        {
            #if PRINT_MMAP_LOOKUP_STATUS
            fprintf(stderr, "file %s is mapped by process %d\n", EVT_PATH, pid);
            #endif
            break;
        }
        else
        {
            #if PRINT_MMAP_LOOKUP_STATUS
            fprintf(stderr, "file %s is not mapped by process %d, retrying...\n", EVT_PATH, pid);
            #endif
            usleep(FILE_LOOKUP_REFRESH_INTERVAL);
        }
    }

    struct stat file_stat;
    fstat(evt_fd, &file_stat);
    long file_size = file_stat.st_size;

    // mmap the embedding vector table
    char* map = mmap(NULL, file_size, PROT_READ, MAP_SHARED, evt_fd, 0);
    if (map == MAP_FAILED)
    {
        fprintf(stderr, "failed to mmap the embedding vector table\n");
        goto clean;
    }

    #if TRACE_TO_STDERR
    fprintf(stderr, "mmaped %s of size %ld bytes at addr %p\n", EVT_PATH, file_size, map);
    #endif

    // flush page cache

    usleep(50000); // wait for 50 milliseconds to "ensure" the file is fully mapped

    #if TRACE_TO_STDERR
    fprintf(stderr, "flushing page cache for %s\n", EVT_PATH);
    #endif

    // for (int i = 0; i < VOCAB_SIZE; i++)
    // {
    //     madvise(map + (long)i * PAGE_SIZE, PAGE_SIZE, MADV_DONTNEED);
    // }
    posix_fadvise(evt_fd, 0, 0, POSIX_FADV_DONTNEED);

    #if TRACE_TO_STDERR
    fprintf(stderr, "starting intercepting\n");
    #endif

    int iteration = 0;
    int prev_token = 1;

    double last_token_time = now_seconds();

    while (1)
    {
        posix_fadvise(evt_fd, 0, 0, POSIX_FADV_DONTNEED);
        // probe the embedding vector table
        for (int i = 0; i < VOCAB_SIZE; i++)
        {
            int cur_token = i;
            char* page_addr = map + (long)i * PAGE_SIZE;
            unsigned char vec[1]; // mincore result vector

            if (mincore(page_addr, PAGE_SIZE, vec) == 0)
            {
                // LSB of the first byte indicates if the page is present in the page cache
                if (vec[0] & 1)
                {
                    #if TRACE_TO_STDERR
                    fprintf(stderr, "------------------------------------------------- iteration %4d\n", iteration);
                    fprintf(stderr, "[%5d] token:%5d | prev_token:%5d  (%s)\n", i, cur_token, prev_token, cur_token == prev_token ? "ignored" : "decoded");
                    #endif
                    char* token_str = decode(&tokenizer, prev_token, cur_token);

                    if (i != 1 && token_str != NULL && cur_token != prev_token)
                    {
                        safe_printf(token_str);
                        fflush(stdout);
                        // record the timestamp of when we got the last token
                        last_token_time = now_seconds();
                        #if TRACE_TO_STDERR
                        fprintf(stderr, "decoded token: %s\n", token_str);
                        #endif
                    }

                    prev_token = cur_token;
                    madvise(page_addr, PAGE_SIZE, MADV_DONTNEED);
                }
            }
        }

        // check if we should exit
        double current_time = now_seconds();
        if (current_time - last_token_time > exit_timeout)
        {
            #if TRACE_TO_STDERR
            fprintf(stderr, "no new tokens for %.2f seconds, exiting...\n", current_time - last_token_time);
            #endif
            break;
        }

        iteration++;
    }

    printf("\n");

clean:
    free_tokenizer(&tokenizer);
    if (map != MAP_FAILED)
    {
        munmap(map, file_size);
    }
    if (evt_fd != -1)
    {
        close(evt_fd);
    }
    return 0;
}