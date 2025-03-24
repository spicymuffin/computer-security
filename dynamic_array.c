#include "dynamic_array.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

// creates a new dynamic array
dynamic_array* dynamic_array_create(size_t initial_capacity, size_t element_size)
{
    if (element_size == 0)
    {
        // element_size must be nonzero or we can’t store anything meaningful
        return NULL;
    }

    dynamic_array* arr = (dynamic_array*)malloc(sizeof(dynamic_array));
    if (!arr)
    {
        // failed to allocate the struct
        return NULL;
    }

    arr->element_size = element_size;
    arr->size = 0;
    arr->capacity = 0;
    arr->data = NULL;

    // if initial_capacity is nonzero, attempt to allocate now
    if (initial_capacity > 0)
    {
        arr->data = malloc(initial_capacity * element_size);
        if (!arr->data)
        {
            // failed to allocate the buffer; free arr and return NULL
            free(arr);
            return NULL;
        }
        arr->capacity = initial_capacity;
    }

    return arr;
}

// frees the dynamic array
void dynamic_array_free(dynamic_array* arr)
{
    if (arr)
    {
        free(arr->data);
        free(arr);
    }
}

// resizes the array buffer to new_capacity in elements
int dynamic_array_resize(dynamic_array* arr, size_t new_capacity)
{
    if (!arr)
    {
        return -1;
    }

    if (new_capacity == 0)
    {
        // if requested capacity is 0, free the buffer and reset everything
        free(arr->data);
        arr->data = NULL;
        arr->size = 0;
        arr->capacity = 0;
        return 0;
    }

    // attempt to reallocate to the new capacity
    void* new_data = realloc(arr->data, new_capacity * arr->element_size);
    if (!new_data)
    {
        // allocation failed
        return -1;
    }

    arr->data = new_data;
    arr->capacity = new_capacity;

    // if we shrank capacity below current size, clamp the size
    if (arr->size > new_capacity)
    {
        arr->size = new_capacity;
    }

    return 0;
}

// pushes (appends) a new element to the end of the array
int dynamic_array_push(dynamic_array* arr, const void* element)
{
    if (!arr)
    {
        return -1;
    }

    // if size equals capacity, we need to grow the buffer
    if (arr->size >= arr->capacity)
    {
        // double the capacity, or go to 1 if it was 0
        size_t new_capacity = (arr->capacity == 0) ? 1 : (arr->capacity * 2);
        if (dynamic_array_resize(arr, new_capacity) < 0)
        {
            // failed to resize, can't push
            return -1;
        }
    }

    // compute the address where the new element should go
    unsigned char* dest = (unsigned char*)arr->data + (arr->size * arr->element_size);

    // copy element_size bytes from 'element' into our array
    memcpy(dest, element, arr->element_size);

    arr->size += 1;
    return 0;
}

// pops the last element of the array
int dynamic_array_pop(dynamic_array* arr, void* out_element)
{
    if (!arr || arr->size == 0)
    {
        // invalid array or empty
        return -1;
    }

    arr->size -= 1;

    if (out_element)
    {
        // copy the popped value out to the user’s buffer
        unsigned char* src = (unsigned char*)arr->data + (arr->size * arr->element_size);
        memcpy(out_element, src, arr->element_size);
    }

    return 0;
}

// returns the current number of elements in the array
size_t dynamic_array_size(const dynamic_array* arr)
{
    if (!arr)
    {
        return 0;
    }
    return arr->size;
}
