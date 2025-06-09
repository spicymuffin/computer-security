#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>      // For open()
#include <unistd.h>     // For close(), usleep()
#include <sys/mman.h>   // For mmap(), munmap(), mincore()
#include <sys/stat.h>   // For fstat()
#include "tokenizer.h"

// embedding vector table path
#define EVT_PATH "embedding_layer.bin"
// tokenizer path
#define TOKENIZER_PATH "tokenizer.bin"
// pagesize
#define PAGE_SIZE 4096

int main(int argc, char* argv[])
{
    Tokenizer tokenizer;
    build_tokenizer(&tokenizer, EVT_PATH, 1000);


clean:
    free_tokenizer(&tokenizer);
    return 0;
}