/**
 * @file cache.c
 * @brief Simple implemention of a doubly-linked list with a least recently used
 *        replacement policy. Modified for web content
 *
 * 18-213: Introduction to Computer Systems
 *
 * @author Ethan Lu <ethanl2@andrew.cmu.edu>
 */

#include "cache.h"

static cache_t *cache;

/**
 * @brief      Initialize the web cache
 * @param[out] Empty cache
 */
void cache_init() {
    cache = Malloc(sizeof(cache_t));
    cache->remaining_space = MAX_CACHE_SIZE;
    cache->cache_head = NULL;
    cache->cache_tail = NULL;
}

/**
 * @brief           Check if there is existing space left in the cache
 * @param[in] space Size of web object
 * @return true     If `remaining_space` is greater than or equal to `space`
 * @return false    Otherwise
 */
bool available_space(size_t space) {
    return cache->remaining_space >= space;
}

/**
 * @brief     Insert `node` at the tail of the cache
 *
 * This function will automatically make space if the cache if
 * additional space is needed.
 *
 * @param[in] node
 */
void insert_node(node_t *node) {
    while (available_space(node->content_size) == false) {
        evict_node();
    }

    /** The cache is empty */
    if (cache->cache_head == NULL && cache->cache_tail == NULL) {
        cache->cache_head = node;
        cache->cache_tail = node;
    } else {
        cache->cache_tail->next = node;
        node->prev = cache->cache_tail;
        cache->cache_tail = cache->cache_tail->next;
        cache->cache_tail->next = NULL;
    }

    cache->remaining_space -= node->content_size;
}

/**
 * @brief     Remove `node` from the cache
 * @param[in] node
 */
void remove_node(node_t *node) {
    /** There is a single block in the cache */
    if (cache->cache_head == node && cache->cache_tail == node) {
        cache->cache_head = NULL;
        cache->cache_tail = NULL;
    } else if (cache->cache_head == node) {
        /** Remove a block from the head of the cache */
        cache->cache_head = cache->cache_head->next;
        cache->cache_head->prev = NULL;
    } else if (cache->cache_tail == node) {
        /** Remove a block from the tail of the cache */
        cache->cache_tail = cache->cache_tail->prev;
        cache->cache_tail->next = NULL;
    } else {
        node->prev->next = node->next;
        node->next->prev = node->prev;
    }

    cache->remaining_space += node->content_size;
}

/**
 * @brief     Search through the cache for an object with the same key as `key`
 * @param[in] key
 * @return    A pointer to the location of the web object
 * @return    NULL otherwise
 */
node_t *search_list(char const *key) {
    /** The cache is empty */
    if (cache->cache_head == NULL && cache->cache_tail == NULL) {
        return NULL;
    }

    node_t *curr_node;
    for (curr_node = cache->cache_head; curr_node != NULL;
         curr_node = curr_node->next) {
        if (strncmp(curr_node->key, key, strlen(curr_node->key)) == 0) {
            remove_node(curr_node);
            insert_node(curr_node);

            return curr_node;
        }
    }

    return NULL;
}

/**
 * @brief Evict a node from the web cache
 *
 * Nodes will be removed based on a LRU replacement policy. In this
 * implemenation, nodes are be removed starting from the head of the cache.
 *
 */
void evict_node() {
    cache->remaining_space += cache->cache_tail->content_size;
    node_t *evicted;
    if (cache->cache_head == cache->cache_tail) {
        evicted = cache->cache_head;
        cache->cache_head = NULL;
        cache->cache_tail = NULL;
    } else {
        evicted = cache->cache_head;
        cache->cache_head = cache->cache_head->next;
    }

    free_node(evicted);
}

/**
 * @brief Create cache node
 *
 * The content for the cache node are heap allocated.
 *
 * @param[in] key
 * @param[in] val
 * @param[in] content_size
 */
node_t *create_node(char *key, char *val, ssize_t content_size) {
    node_t *node = Malloc(sizeof(node_t));

    node->key = Malloc(strlen(key));
    memcpy(node->key, key, strlen(key));

    node->val = Malloc(content_size);
    memcpy(node->val, val, content_size);

    node->content_size = content_size;

    node->next = NULL;
    node->prev = NULL;

    return node;
}

/**
 * @brief Free a cache node
 */
void free_node(node_t *node) {
    Free(node->key);
    Free(node->val);
    Free(node);
}
