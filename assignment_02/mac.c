#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dynamic_array.h>

typedef struct access_level
{
    char* name;
    int level;
} access_level;


int main(int argc, char* argv[])
{
    // read mac.policy on startup to determine user privileges


    // drop root privileges by using setuid, seteuid, setgid, setegid


    return 0;
}