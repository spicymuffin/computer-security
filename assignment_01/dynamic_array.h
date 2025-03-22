#ifndef DYNAMIC_ARRAY_H
#define DYNAMIC_ARRAY_H

#include <stddef.h>

/* the dynamic_array struct */
typedef struct dynamic_array
{
   void* data;           /* pointer to the underlying buffer */
   size_t element_size;  /* size (in bytes) of each element */
   size_t size;          /* number of elements in the array */
   size_t capacity;      /* maximum number of elements before a resize is required */
} dynamic_array;

/* creates a new dynamic array
   - initial_capacity is how many elements to reserve at the start
   - element_size is the size in bytes of the type you want to store
   returns a pointer to a newly allocated dynamic_array, or NULL on failure */
dynamic_array* dynamic_array_create(size_t initial_capacity, size_t element_size);

/* frees all memory associated with the dynamic array (safe to pass NULL) */
void dynamic_array_free(dynamic_array* arr);

/* resizes the array buffer to new_capacity (in elements), returns 0 on success, -1 on error */
int dynamic_array_resize(dynamic_array* arr, size_t new_capacity);

/* appends a new element to the end of the array
   - element is a pointer to the data you want to store
   returns 0 on success, -1 on error */
int dynamic_array_push(dynamic_array* arr, const void* element);

/* removes the last element of the array
   - out_element is a pointer where the popped element will be copied
   - if out_element is NULL, the popped element is discarded
   returns 0 on success, -1 if the array is empty or invalid */
int dynamic_array_pop(dynamic_array* arr, void* out_element);

/* returns the current number of elements in the array */
size_t dynamic_array_size(const dynamic_array* arr);

#endif
