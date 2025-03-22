#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "secure_house.h"
#include "dynamic_array.h"

#define DEBUG 0

typedef enum lock_enum
{
    LOCKED, // inital
    KEY_IN, // key inserted
    TURNED, // key turned, possible to enter
} lock_enum;

typedef struct lock_state
{
    lock_enum le;
    char* inserted_key;
    size_t inserted_key_len;
} lock_state;

typedef struct in_house_ll_node
{
    char* name;
    size_t name_len;
    struct in_house_ll_node* next;
    struct in_house_ll_node* prev;
} in_house_ll_node;

lock_state ls = { LOCKED, NULL, 0 };

char* owner_name = NULL;
in_house_ll_node in_house_ll_head = { NULL, 0, NULL, NULL };

dynamic_array* keys = NULL;
int key_count = 0;

char* alloc_and_cpy(char* src, size_t len)
{
    char* dst = malloc(len + 1); // +1 for null terminator
    strncpy(dst, src, len);
    dst[len] = '\0';

    return dst;
}

int check_key_validity(char* key, size_t key_len)
{
    if (key_count == 0)
    {
        return 0;
    }

    // check firefighter secret key
    if (key_len == FIREFIGHTER_SECRET_KEY_LEN && (strncmp(key, FIREFIGHTER_SECRET_KEY, FIREFIGHTER_SECRET_KEY_LEN) == 0))
    {
        return 1;
    }

    char** dataptr = keys->data;

    for (int i = 0; i < key_count; i++)
    {
        /// TODO: cache key length in the keys array to speed up this check
        if (strlen(dataptr[i]) == key_len && strncmp(dataptr[i], key, key_len) == 0)
        {
            return 1;
        }
    }

    return 0;
}

void reset_ls()
{
    ls.le = LOCKED;
    free(ls.inserted_key);
    ls.inserted_key = NULL;
    ls.inserted_key_len = 0;
}

void in_house_ll_insert_after_node(in_house_ll_node* node, in_house_ll_node* new_node)
{
    in_house_ll_node* next = node->next;
    in_house_ll_node* prev = node;

    new_node->next = next;
    new_node->prev = prev;

    next->prev = new_node;
    prev->next = new_node;
}

in_house_ll_node* in_house_ll_contains(char* name, size_t name_len)
{
    in_house_ll_node* current = in_house_ll_head.next;

    while (current != &in_house_ll_head)
    {
        if (current->name_len == name_len && strncmp(current->name, name, name_len) == 0)
        {
            return current;
        }

        current = current->next;
    }

    return NULL;
}

void in_house_ll_remove(in_house_ll_node* node)
{
    in_house_ll_node* next = node->next;
    in_house_ll_node* prev = node->prev;

    next->prev = prev;
    prev->next = next;
}

void destroy_in_house_ll_node(in_house_ll_node* node)
{
    free(node->name);
    free(node);
}

in_house_ll_node* create_in_house_ll_node(char* name, size_t name_len)
{
    in_house_ll_node* new_node = malloc(sizeof(in_house_ll_node));
    new_node->name_len = name_len;
    new_node->name = alloc_and_cpy(name, name_len);
    return new_node;
}

int main(int argc, char* argv[])
{
    if (argc < 2)
    {
        printf("Usage: <owner_name> <key1> ... <keyn>\n");
        return 1;
    }

    owner_name = argv[1];

    // calculate initial # of keys
    key_count = argc - 2;
    // allocate nodes for initial keys
    keys = dynamic_array_create(key_count, sizeof(char*));

    for (int i = 0; i < key_count; i++)
    {
        size_t key_len = strlen(argv[i + 2]);

        char* key = alloc_and_cpy(argv[i + 2], key_len);

        char** dataptr = keys->data;
        dataptr[i] = key;
    }

    // initialize in_house linked list
    in_house_ll_head.name = NULL;
    in_house_ll_head.next = &in_house_ll_head;
    in_house_ll_head.prev = &in_house_ll_head;

    char* line = NULL;
    size_t len = 0;

    while (getline(&line, &len, stdin) != -1)
    {
        // exit if empty line
        if (line[0] == '\n')
        {
            free(line);
            return 0;
        }

        line[strcspn(line, "\n")] = 0; // remove newline

        // 6 possible inputs
        // INSERT KEY <user_name> <key>
        // TURN KEY <user_name>
        // ENTER HOUSE <user_name
        // WHO'S INSIDE?
        // CHANGE LOCKS <user_name> <key_1> <key_2> ... <key_n>
        // LEAVE HOUSE <user_name>

        // exploit the fact that the first letter of each command is unique
        switch (line[0])
        {
        case 'I':
            // INSERT KEY
            if (strncmp(line, "INSERT KEY ", 11) == 0)
            {
                char* user_name = NULL;
                char* key = NULL;
                char* leftover = NULL;

                // parse user_name and key from input
                user_name = strtok(line + 11, " ");
                if (user_name == NULL) goto invalid_input;
                key = strtok(NULL, " ");
                if (key == NULL) goto invalid_input;
                leftover = strtok(NULL, " ");
                if (leftover != NULL) goto invalid_input;
                // input valid, commit to command

                // reset lock state since a new key is inserted (like even the lock gets relocked)
                reset_ls();

                ls.le = KEY_IN;

                size_t key_len = strlen(key);
                ls.inserted_key_len = key_len;

                ls.inserted_key = alloc_and_cpy(key, key_len);

                printf("KEY %s INSERTED BY %s\n", key, user_name);
            }
            else
            {
                goto invalid_input;
            }

            break;

        case 'T':
            // TURN KEY
            if (strncmp(line, "TURN KEY ", 9) == 0)
            {
                char* user_name = NULL;
                char* leftover = NULL;

                // parse user_name from input
                user_name = strtok(line + 9, " ");
                if (user_name == NULL) goto invalid_input;
                leftover = strtok(NULL, " ");
                if (leftover != NULL) goto invalid_input;
                // input valid, commit to command

                if (ls.inserted_key_len == 0)
                {
                    printf("FAILURE %s HAD NO KEY INSERTED\n", user_name);
                }
                else if (check_key_validity(ls.inserted_key, ls.inserted_key_len) == 0)
                {
                    printf("FAILURE %s HAD INVALID KEY %s INSERTED\n", user_name, ls.inserted_key);
                }
                else
                {
                    ls.le = TURNED;
                    printf("SUCCESS %s TURNS KEY %s\n", user_name, ls.inserted_key);
                }
            }
            else
            {
                goto invalid_input;
            }

            break;

        case 'E':
            // ENTER HOUSE
            if (strncmp(line, "ENTER HOUSE ", 12) == 0)
            {
                char* user_name = NULL;
                char* leftover = NULL;

                // parse user_name from input
                user_name = strtok(line + 12, " ");
                if (user_name == NULL) goto invalid_input;
                leftover = strtok(NULL, " ");
                if (leftover != NULL) goto invalid_input;
                // input valid, commit to command

                if (ls.le != TURNED)
                {
                    printf("ACCESS DENIED\n");
                }
                else
                {
                    size_t name_len = strlen(user_name);

                    in_house_ll_node* new_node = create_in_house_ll_node(user_name, name_len);
                    in_house_ll_insert_after_node(&in_house_ll_head, new_node);

                    reset_ls();

                    printf("ACCESS ALLOWED\n");
                }

            }
            else
            {
                goto invalid_input;
            }

            break;

        case 'W':
            // WHO'S INSIDE?
            if (strncmp(line, "WHO'S INSIDE?", 13) == 0 && strlen(line) == 13)
            {
                // print in reverse so earlier accesses are printed first
                in_house_ll_node* current = in_house_ll_head.prev;

                if (current == &in_house_ll_head)
                {
                    printf("NOBODY HOME\n");
                    break;
                }

                if (current != &in_house_ll_head)
                {
                    printf("%s", current->name);
                    current = current->prev;
                }

                while (current != &in_house_ll_head)
                {
                    printf(", %s", current->name);
                    current = current->prev;
                }

                printf("\n");
            }
            else
            {
                goto invalid_input;
            }

            break;

        case 'C':
            // CHANGE LOCKS
            if (strncmp(line, "CHANGE LOCKS ", 13) == 0)
            {
                char* user_name = NULL;
                char* key = NULL;

                // parse user_name and keys from input
                user_name = strtok(line + 13, " ");
                if (user_name == NULL) goto invalid_input;
                // input valid, commit to command

                // check if owner is inside the house
                if (in_house_ll_contains(owner_name, strlen(owner_name)) == NULL)
                {
                    printf("LOCK CHANGE DENIED\n");
                    break;
                }

                if (strlen(user_name) != strlen(owner_name) || strcmp(user_name, owner_name) != 0)
                {
                    printf("LOCK CHANGE DENIED\n");
                    break;
                }

                // free previous keys
                char** dataptr = keys->data;
                for (int i = 0; i < key_count; i++)
                {
                    free(dataptr[i]);
                }

                // reset key count
                key_count = 0;

                // resize keys array
                dynamic_array_resize(keys, 0);

                // read new keys
                while ((key = strtok(NULL, " ")) != NULL)
                {
                    size_t key_len = strlen(key);

                    char* new_key = alloc_and_cpy(key, key_len);

                    dynamic_array_push(keys, &new_key);

                    key_count++;
                }

                reset_ls();

                printf("LOCK CHANGED\n");
            }
            else
            {
                goto invalid_input;
            }

            break;

        case 'L':
            // LEAVE HOUSE
            if (strncmp(line, "LEAVE HOUSE ", 12) == 0)
            {
                char* user_name = NULL;
                char* leftover = NULL;

                // parse user_name from input
                user_name = strtok(line + 12, " ");
                if (user_name == NULL) goto invalid_input;
                leftover = strtok(NULL, " ");
                if (leftover != NULL) goto invalid_input;
                // input valid, commit to command

                size_t name_len = strlen(user_name);

                in_house_ll_node* node;
                if ((node = in_house_ll_contains(user_name, name_len)) == NULL)
                {
                    printf("%s NOT HERE\n", user_name);
                }
                else
                {
                    in_house_ll_remove(node);
                    destroy_in_house_ll_node(node);

                    printf("%s LEFT\n", user_name);
                }
            }
            else
            {
                goto invalid_input;
            }

            break;

            #if DEBUG

        case 'P':
            // PRINT KEYS
            for (int i = 0; i < key_count; i++)
            {
                printf("%s ", ((char**)keys->data)[i]);
            }

            printf("\n");

            break;
            #endif

        invalid_input:
        default:
            printf("ERROR\n");
            break;
        }

        // free line buffer
        free(line);
        line = NULL;
    }

    free(line);
    line = NULL;

    // free keys
    char** dataptr = keys->data;
    for (int i = 0; i < key_count; i++)
    {
        free(dataptr[i]);
    }

    // free dynamic array
    dynamic_array_free(keys);

    // free in_house linked list
    in_house_ll_node* current = in_house_ll_head.next;
    while (current != &in_house_ll_head)
    {
        in_house_ll_node* next = current->next;
        destroy_in_house_ll_node(current);
        current = next;
    }

    return 0;
}