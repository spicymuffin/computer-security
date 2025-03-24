#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

#include "mac.h"
#include "dynamic_array.h"

#include <unistd.h>
#include <pwd.h>
#include <sys/types.h>
#include <sys/stat.h>

#define DEBUG 0

typedef struct user_access_level
{
    char* name;
    int name_len;
} user_access_level;

typedef struct id_data
{
    uid_t ruid;
    uid_t euid;
    gid_t rgid;
    gid_t egid;

    struct passwd* pw;
} id_data;

id_data idd;

void init_id_data()
{
    idd.ruid = getuid();
    idd.euid = geteuid();
    idd.rgid = getgid();
    idd.egid = getegid();
    idd.pw = getpwuid(idd.ruid);
}

int drop_privileges()
{
    if (seteuid(idd.ruid) == -1)
    {
        fprintf(stderr, "drop privileges: setuid failed\n");
        return 1;
    }

    if (setegid(idd.rgid) == -1)
    {
        fprintf(stderr, "drop privileges: setgid failed\n");
        return 1;
    }

    return 0;
}


void destroy_access_level(user_access_level* al)
{
    free(al->name);
}

typedef struct mac_policy
{
    dynamic_array* access_levels[N_ACCESS_LEVELS];
} mac_policy;

void destroy_mac_policy(mac_policy* policy)
{
    for (int i = 0; i < N_ACCESS_LEVELS; i++)
    {
        dynamic_array* level = (policy->access_levels)[i];
        for (size_t j = 0; j < dynamic_array_size(level); j++)
        {
            user_access_level* al = &(((user_access_level*)(level->data))[j]);
            destroy_access_level(al);
        }
        dynamic_array_free(level);
    }
}

void print_mac_policy(mac_policy* policy)
{
    for (int i = 0; i < N_ACCESS_LEVELS; i++)
    {
        dynamic_array* level = (policy->access_levels)[i];
        for (size_t j = 0; j < dynamic_array_size(level); j++)
        {
            user_access_level* al = &(((user_access_level*)(level->data))[j]);
            printf("name: %s, level: %d (%s)\n", al->name, i, access_level_strings[i]);
        }
    }
}

void mac_policy_init(mac_policy* policy)
{
    // initialize the access_levels array
    for (int i = 0; i < N_ACCESS_LEVELS; i++)
    {
        policy->access_levels[i] = dynamic_array_create(0, sizeof(user_access_level));
    }

    // read mac.policy file and populate the access_levels array
    FILE* file = fopen("mac.policy", "r");
    if (!file)
    {
        fprintf(stderr, "mac.policy file read failed\n");
        destroy_mac_policy(policy);
        exit(1);
    }

    char* line = NULL;
    size_t len = 0;

    while (getline(&line, &len, file) != -1)
    {
        char* name = strtok(line, ":");
        char* level = strtok(NULL, "\n");
        size_t level_len = strlen(level);
        int tmp_level = -1;

        if (!name || !level)
        {
            fprintf(stderr, "invalid mac.policy file format\n");
            destroy_mac_policy(policy);
            free(line);
            exit(1);
        }

        user_access_level al;
        // write name
        al.name = strdup(name);
        al.name_len = strlen(name);

        // determine level
        if (strcmp(level, TOP_SECRET_LIT) == 0 && level_len == TOP_SECRET_LEN)
        {
            tmp_level = TOP_SECRET;
        }
        else if (strcmp(level, SECRET_LIT) == 0 && level_len == SECRET_LEN)
        {
            tmp_level = SECRET;
        }
        else if (strcmp(level, CONFIDENTIAL_LIT) == 0 && level_len == CONFIDENTIAL_LEN)
        {
            tmp_level = CONFIDENTIAL;
        }
        else if (strcmp(level, UNCLASSIFIED_LIT) == 0 && level_len == UNCLASSIFIED_LEN)
        {
            tmp_level = UNCLASSIFIED;
        }
        else
        {
            fprintf(stderr, "invalid entry in mac.policy file\n");
            destroy_mac_policy(policy);
            free(line);
            exit(1);
        }
        // this is okay because dynamic array uses memcpy to copy the element
        dynamic_array_push(policy->access_levels[tmp_level], &al);

        free(line);
        line = NULL;
    }

    free(line);
    line = NULL;
    fclose(file);
}

int map_filename_to_access_level(mac_policy* policy, char* filename)
{
    // map the filename to an access level
    // if the filename is not found, return -1
    // leveraging the fact that all filenames have unique first character
    switch (*filename)
    {
    case 't':
        // top secret
        return TOP_SECRET;
    case 's':
        // secret
        return SECRET;
    case 'c':
        // confidential
        return CONFIDENTIAL;
    case 'u':
        // unclassified
        return UNCLASSIFIED;
    default:
        return -1;
    }
}

int check_if_in_access_level(mac_policy* policy, char* username, size_t username_len, int access_level)
{
    // check if the user is in the access level
    // if the user is in the access level, return 1
    // if the user is not in the access level, return 0

    // iterate over the access level and check if the user is in the access level
    for (size_t i = 0; i < dynamic_array_size(policy->access_levels[access_level]); i++)
    {
        user_access_level* al = (policy->access_levels[access_level]->data);
        al += i;
        if (strncmp(al->name, username, al->name_len) == 0 && username_len == al->name_len)
        {
            return 1;
        }
    }

    return 0;
}

int check_read_authority(mac_policy* policy, char* username, size_t username_len, int file_access_level)
{
    // check if the user has read authority for the file
    // if the user has read authority, return 1
    // if the user does not have read authority, return 0
    // read down so if the user has higher access level, they can read lower levels
    // so we need to check from if the user is present in higher access levels
    // (higher level = higher index in the access_levels array)
    // (S can read O iff Is >= Io)

    for (int i = file_access_level; i < N_ACCESS_LEVELS; i++)
    {
        // check if the user is in the access level
        if (check_if_in_access_level(policy, username, username_len, i))
        {
            return 1;
        }
    }

    return 0;
}

int check_write_authority(mac_policy* policy, char* username, size_t username_len, int file_access_level)
{
    // check if the user has write authority for the file
    // if the user has write authority, return 1
    // if the user does not have write authority, return 0
    // write up so if the user has lower access level, they can write higher levels
    // so we need to check from if the user is present in lower access levels
    // (lower level = lower index in the access_levels array)
    // (S can write O iff Is <= Io)

    for (int i = file_access_level; i >= 0; i--)
    {
        // check if the user is in the access level
        if (check_if_in_access_level(policy, username, username_len, i))
        {
            return 1;
        }
    }

    return 0;
}

int write_to_log(char* username, size_t username_len, char* operation, char* filename)
{
    // log the command
    char* log_filename = malloc(username_len + 5);
    snprintf(log_filename, username_len + 5, "%s.log", username);

    /// TODO: is this right even
    umask(0137);  // ensures file is created with at most 0640 (rw-r-----)

    int fd = open(log_filename, O_WRONLY | O_CREAT | O_APPEND, 0640);
    if (fd == -1)
    {
        fprintf(stderr, "log write: open failed\n");
        free(log_filename);
        return 1;
    }

    dprintf(fd, "%s %s\n", operation, filename);
    fsync(fd);
    close(fd);
    free(log_filename);

    return 0;
}

void write_file(mac_policy* policy, char* username, size_t username_len, char* filename, char* message)
{
    int file_access_level = map_filename_to_access_level(policy, filename);
    if (file_access_level == -1)
    {
        fprintf(stderr, "write: invalid filename\n");
        destroy_mac_policy(policy);
        exit(1);
    }

    // check authority to write the file
    int auth = check_write_authority(policy, username, username_len, file_access_level);

    if (!auth)
    {
        if (drop_privileges())
        {
            fprintf(stderr, "drop privileges: failed\n");
        }

        printf("ACCESS DENIED\n");

        // log the command
        if (write_to_log(username, username_len, "write", filename))
        {
            fprintf(stderr, "log write: failed\n");
        }

        destroy_mac_policy(policy);
        exit(1);
    }

    // open the file for appending (assumed to exist)
    int fd = open(filename, O_WRONLY | O_APPEND);
    if (fd == -1)
    {
        fprintf(stderr, "write: open failed\n");
        destroy_mac_policy(policy);
        exit(1);
    }

    // write the message to the file
    dprintf(fd, "%s\n", message);
    fsync(fd);
    close(fd);

    if (drop_privileges())
    {
        destroy_mac_policy(policy);
        exit(1);
    }

    // log the command
    if (write_to_log(username, username_len, "write", filename))
    {
        destroy_mac_policy(policy);
        fprintf(stderr, "log write: failed\n");
        exit(1);
    }
}

void read_file(mac_policy* policy, char* username, size_t username_len, char* filename)
{
    int file_access_level = map_filename_to_access_level(policy, filename);
    if (file_access_level == -1)
    {
        fprintf(stderr, "write: invalid filename\n");
        destroy_mac_policy(policy);
        exit(1);
    }

    // check authority to read the file
    int auth = check_read_authority(policy, username, username_len, file_access_level);

    if (!auth)
    {
        if (drop_privileges())
        {
            fprintf(stderr, "drop privileges: failed\n");
        }

        printf("ACCESS DENIED\n");

        // log the command
        if (write_to_log(username, username_len, "read", filename))
        {
            fprintf(stderr, "log write: failed\n");
        }

        destroy_mac_policy(policy);
        exit(1);
    }

    FILE* file = fopen(filename, "r");
    if (file == NULL)
    {
        fprintf(stderr, "read: open failed\n");
        destroy_mac_policy(policy);
        exit(1);
    }

    char buffer[1024];
    while (fgets(buffer, sizeof(buffer), file) != NULL)
    {
        fputs(buffer, stdout);
    }
    fclose(file);
    printf("\n");

    if (drop_privileges())
    {
        destroy_mac_policy(policy);
        exit(1);
    }

    // log the command
    if (write_to_log(username, username_len, "read", filename))
    {
        destroy_mac_policy(policy);
        fprintf(stderr, "log write: failed\n");
        exit(1);
    }
}

int main(int argc, char* argv[])
{
    // read mac.policy on startup to determine user privileges
    mac_policy policy;
    mac_policy_init(&policy);

    init_id_data();

    #if DEBUG
    print_mac_policy(&policy);
    if (idd.pw != NULL)
    {
        printf("username: %s\n", idd.pw->pw_name);
    }
    #endif

    size_t username_len = strlen(idd.pw->pw_name);
    char* username = malloc(username_len + 1);
    strncpy(username, idd.pw->pw_name, username_len);
    username[username_len] = '\0';

    #if DEBUG
    printf("real UID: %d\n", idd.ruid);
    printf("effective UID: %d\n", idd.euid);
    printf("real GID: %d\n", idd.rgid);
    printf("effective GID: %d\n", idd.egid);
    #endif

    // parse command line arguments
    if (argc < 3)
    {
        fprintf(stderr, "usage: %s read/write args...\n", argv[0]);
        destroy_mac_policy(&policy);
        exit(2);
    }
    else if (strcmp(argv[1], "read") == 0 && strlen(argv[1]) == 4)
    {
        // read to file
        read_file(&policy, username, username_len, argv[2]);
    }
    else if (argc >= 4 && strcmp(argv[1], "write") == 0 && strlen(argv[1]) == 5)
    {
        // write to file
        write_file(&policy, username, username_len, argv[2], argv[3]);
    }
    else
    {
        fprintf(stderr, "invalid command\n");
        destroy_mac_policy(&policy);
        exit(1);
    }

    destroy_mac_policy(&policy);
    free(username);

    return 0;
}