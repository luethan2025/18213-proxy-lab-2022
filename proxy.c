/**
 * @file proxy.c
 * @brief A proxy web server
 *
 * 18-213: Introduction to Computer Systems
 *
 * The proxy web server acts an intermediary between the client requesting a
 * resource and the server providing that resource. The client will send their
 * request to the proxy server and the proxy server will then forward that
 * request to the server. Once the server responses to the request, the proxy
 * will then forward the resource back to the client. If this web object is less
 * than or equal to 102,400 bytes, the proxy will cache this object. If the
 * cache is full, the total size of the cache is greater than 1,048,576 bytes,
 * the cache will evict objects based on a least recently used policy.
 *
 * @author Ethan Lu <ethanl2@andrew.cmu.edu>
 */

#include "cache.h"
#include "csapp.h"

#include <assert.h>
#include <ctype.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

#include <http_parser.h>

#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>

/*
 *  * Debug macros, which can be enabled by adding -DDEBUG in the Makefile
 *   * Use these if you find them useful, or delete them if not
 *    */
#ifdef DEBUG
#define dbg_assert(...) assert(__VA_ARGS__)
#define dbg_printf(...) fprintf(stderr, __VA_ARGS__)
#else
#define dbg_assert(...)
#define dbg_printf(...)
#endif

/** @brief Constants used to build the client request */
static const char *header_host = "Host: %s:%s\r\n";
static const char *header_request = "GET %s HTTP/1.0\r\n";
static const char *header_user_agent = "User-Agent: Mozilla/5.0"
                                       " (X11; Linux x86_64; rv:3.10.0)"
                                       " Gecko/20191101 Firefox/63.0.1\r\n";
static const char *header_connection = "Connection: close\r\n";
static const char *header_proxy = "Proxy-Connection: close\r\n";
static const char *header_terminating = "\r\n";

/** @brief Constants used to match the server response */
static const char *key_host = "Host :";
static const char *key_agent = "User-Agent: ";
static const char *key_connection = "Connection: ";
static const char *key_proxy = "Proxy-Connection: ";

/** @brief Formatting for the url */
static char *url_template = "http://%s:%s%s";

/** @brief Forward declaration of functions */
static void exchange_data(int connfd);
static void build_header(char *header, const char *hostname, const char *port,
                         const char *path, rio_t client);
static bool parse_relevant(char *buf);
static void assemble_header(char *header, char *request, char *host_header,
                            char *other_header);
static void cleanup(parser_t **p, int *connfd, int *serverfd);
static void clienterror(int fd, const char *errnum, const char *shortmsg,
                        const char *longmsg);
static void *thread(void *vargp);

pthread_mutex_t mutex;
cache_t *cache;

/**
 * @brief     Proxy main routine
 * @param[in] argc
 * @param[in] argv
 */
int main(int argc, char **argv) {
    int listenfd, *connfdp;
    socklen_t clientlen;
    struct sockaddr_storage clientaddr;
    pthread_t tid;

    if (argc != 2) {
        fprintf(stderr, "usage: %s <port>\n", argv[0]);
        exit(0);
    }

    Signal(SIGPIPE, SIG_IGN);

    if ((listenfd = open_listenfd(argv[1])) < 0) {
        fprintf(stderr, "Failed to listen on port: %s\n", argv[1]);
    }

    pthread_mutex_init(&mutex, NULL);
    cache_init();

    while (1) {
        connfdp = Malloc(sizeof(int));
        *connfdp = accept(listenfd, (struct sockaddr *)&clientaddr, &clientlen);
        pthread_create(&tid, NULL, thread, connfdp);
    }
    // clean resources here
    return 1;
}

/**
 * @brief     Creates a thread, and runs its routine
 * @param[in] vargp
 */
void *thread(void *vargp) {
    int connfd = *((int *)vargp);
    pthread_detach(pthread_self());
    Free(vargp);
    exchange_data(connfd);
    return NULL;
}

/**
 * @brief     Exchange data between the client and server and server and
 *            client
 * @param[in] connfd The connection file descriptor
 */
void exchange_data(int connfd) {
    parser_t *p = parser_new();
    rio_t client, server;
    int serverfd;

    char buf[MAXLINE];
    char http_header[MAXLINE];

    const char *method, *hostname, *port, *path, *version;
    const char *uri;
    int valid_method, valid_hostname, valid_port, valid_path, valid_version;
    int valid_uri;

    char url[MAXLINE];

    rio_readinitb(&client, connfd);
    rio_readlineb(&client, buf, MAXLINE);

    /** Parser error status */
    parser_state state = parser_parse_line(p, buf);
    if (state == ERROR) {
        fprintf(stderr, "Proxy parser has failed\n");
        cleanup(&p, &connfd, NULL);
        return;
    }

    valid_method = parser_retrieve(p, METHOD, &method);
    valid_hostname = parser_retrieve(p, HOST, &hostname);
    valid_port = parser_retrieve(p, PORT, &port);
    valid_path = parser_retrieve(p, PATH, &path);
    valid_version = parser_retrieve(p, HTTP_VERSION, &version);
    valid_uri = parser_retrieve(p, URI, &uri);

    /** HTTP 400 error status */
    if (valid_method == -1 || valid_hostname == -1 || valid_port == -1 ||
        valid_path == -1 || valid_version == -1 || valid_uri == -1) {
        clienterror(connfd, "400", "Bad Request",
                    "Proxy recieved a malformed request");
        cleanup(&p, &connfd, NULL);
        return;
    }

    if (valid_method == -2 || valid_hostname == -2 || valid_path == -2 ||
        valid_version == -2 || valid_uri == -2) {
        clienterror(connfd, "400", "Bad Request",
                    "Proxy could not parse the request");
        cleanup(&p, &connfd, NULL);
        return;
    }

    /** HTTP 501 error status */
    if (strcmp("GET", method) != 0) {
        clienterror(connfd, "501", "Not Implemented",
                    "Proxy does not implement this method\n");
        cleanup(&p, &connfd, NULL);
        return;
    }

    /** HTTP 505 error status */
    if (strcmp("1.0", version) != 0 && strcmp("1.1", version) != 0) {
        clienterror(connfd, "505", "HTTP Version Not Supported",
                    "Proxy does not support this HTTP version\n");
        cleanup(&p, &connfd, NULL);
        return;
    }

    /** Set `port` to the default port if neccessary*/
    if (valid_port == -2) {
        port = "80";
    }

    sprintf(url, url_template, hostname, port, path);
    pthread_mutex_lock(&mutex);
    node_t *node = search_list(uri);
    pthread_mutex_unlock(&mutex);

    if (node == NULL) {
        build_header(http_header, hostname, port, path, client);

        /** Send our request to the server */
        serverfd = open_clientfd(hostname, port);
        rio_readinitb(&server, serverfd);
        if (rio_writen(serverfd, http_header, strlen(http_header)) < 0) {
            fprintf(stderr, "Error writing response header to client");
            cleanup(&p, &connfd, &serverfd);
            return;
        }

        /** Read the response from the server */
        ssize_t n;
        ssize_t content_size = 0;
        char response[MAX_OBJECT_SIZE];

        while ((n = rio_readnb(&server, buf, MAXLINE)) > 0) {
            if (rio_writen(connfd, buf, n) < 0) {
                cleanup(&p, &connfd, &serverfd);
                return;
            }

            if (content_size + n <= MAX_OBJECT_SIZE) {
                memcpy(response + content_size, buf, n);
            }

            content_size += n;
        }

        if (content_size <= MAX_OBJECT_SIZE) {
            pthread_mutex_lock(&mutex);
            node_t *new_node = create_node(url, response, content_size);
            insert_node(new_node);
            pthread_mutex_unlock(&mutex);
        }
    } else {
        /** Response with the cached response */
        rio_writen(connfd, node->val, node->content_size);
        cleanup(&p, &connfd, NULL);
        return;
    }

    cleanup(&p, &connfd, &serverfd);
}

/**
 * @brief      Build the request header
 * @param[out] header  A pointer to a location in memory to construct the
 * request header
 * @param[in]  host    Hostname
 * @param[in]  port    Desired port
 * @param[in]  path    Requested path
 * @param[in]  client  Client request
 */
void build_header(char *header, const char *host, const char *port,
                  const char *path, rio_t client) {
    char buf[MAXLINE], request[MAXLINE];
    char host_header[MAXLINE], other_header[MAXLINE];

    snprintf(request, MAXLINE, header_request, path);

    /** Safety clears of stack allocated buffers */
    memset(header, 0, MAXLINE);
    memset(host_header, 0, MAXLINE);
    memset(other_header, 0, MAXLINE);

    /** Read through the client request*/
    ssize_t n;
    while ((n = rio_readlineb(&client, buf, MAXLINE)) > 0) {
        if (strncmp(buf, header_terminating, strlen(header_terminating)) == 0) {
            break;
        }

        if (strncmp(buf, key_host, strlen(key_host)) == 0) {
            strcat(host_header, buf);
            continue;
        }

        if (parse_relevant(buf)) {
            strcat(other_header, buf);
        }
    }

    /** If host header is empty add our own host and port */
    if (strlen(host_header) == 0) {
        snprintf(host_header, MAXLINE, header_host, host, port);
    }

    assemble_header(header, request, host_header, other_header);
}

/**
 * @brief     Check if a section of the buffer contains important information
 * @param[in] buf
 */
bool parse_relevant(char *buf) {
    /**
     *  Only extract information that is not the user-agent, connection, or
     *  proxy-connection
     */
    if (strncmp(buf, key_agent, strlen(key_agent)) == 0 ||
        strncmp(buf, key_connection, strlen(key_connection)) == 0 ||
        strncmp(buf, key_proxy, strlen(key_proxy)) == 0) {
        return false;
    }
    return true;
}

/**
 * @brief     Assemble the request header
 * @param[in] header     A pointer to a location in memory to construct the
 *                       request header
 * @param[in] request    Request line
 * @param[in] host_head  Hostname
 * @param[in] other_head Additional information sent by the client
 */
void assemble_header(char *header, char *request, char *host_header,
                     char *other_header) {
    strcat(header, request);
    strcat(header, host_header);
    strcat(header, header_user_agent);
    strcat(header, header_connection);
    strcat(header, header_proxy);
    strcat(header, other_header);
    strcat(header, header_terminating);
}

/**
 * @brief     Cleans up resources
 * @param[in] p        HTTP parser
 * @param[in] connfd   Connection file descriptor
 * @param[in] serverfd Server file descriptor
 */
void cleanup(parser_t **p, int *connfd, int *serverfd) {
    if (p != NULL) {
        parser_free(*p);
    }

    if (connfd != NULL) {
        close(*connfd);
    }

    if (serverfd != NULL) {
        close(*serverfd);
    }
}

/**
 * @brief     Writes an error back to the client
 * @param[in] fd
 * @param[in] errnum
 * @param[in] shortmsg
 * @param[in] longmsg
 */
void clienterror(int fd, const char *errnum, const char *shortmsg,
                 const char *longmsg) {
    char buf[MAXLINE];
    char body[MAXBUF];
    size_t buflen;
    size_t bodylen;

    /* build the HTTP response body */
    bodylen = snprintf(body, MAXBUF,
                       "<!DOCTYPE html>\r\n"
                       "<html>\r\n"
                       "<head><title>Proxy Error</title></head>\r\n"
                       "<body bgcolor=\"ffffff\">\r\n"
                       "<h1>%s: %s</h1>\r\n"
                       "<p>%s</p>\r\n"
                       "<hr /><em>The Proxy Web server</em>\r\n"
                       "</body></html>\r\n",
                       errnum, shortmsg, longmsg);

    if (bodylen >= MAXBUF) {
        return;
    }

    buflen = snprintf(buf, MAXLINE,
                      "HTTP/1.0 %s %s\r\n"
                      "Content-Type: text/html\r\n"
                      "Content-Length: %zu\r\n\r\n",
                      errnum, shortmsg, bodylen);
    if (buflen >= MAXLINE) {
        return;
    }

    if (rio_writen(fd, buf, buflen) < 0) {
        fprintf(stderr, "Error writing error response headers to client\n");
        return;
    }
    if (rio_writen(fd, body, bodylen) < 0) {
        fprintf(stderr, "Error writing error response body to client\n");
        return;
    }
}
