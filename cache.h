/**
 * @file cache.h
 * @brief Protypes and definitions for the web cache
 */

#include "csapp.h"

#include <stdbool.h> /* bool */
#include <stdio.h>   /* stderr */
#include <string.h>  /* memcpy */

/* Cache constants */
#define MAX_CACHE_SIZE (1024 * 1024)
#define MAX_OBJECT_SIZE (100 * 1024)

/** @brief Represents a node in the web cache */
typedef struct node {
    char *key;
    char *val;
    ssize_t content_size;
    struct node *prev;
    struct node *next;
} node_t;

/** @brief Represents the web cache */
typedef struct cache {
    node_t *cache_head;
    node_t *cache_tail;
    size_t remaining_space;
    size_t node_count;
} cache_t;

/** @brief Basic cache functions */
void cache_init();
bool available_space(size_t space);
void insert_node(node_t *node);
void remove_node(node_t *node);
node_t *search_list(char const *key);
void evict_node();
node_t *create_node(char *key, char *val, ssize_t content_size);
void free_node(node_t *node);
