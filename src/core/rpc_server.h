#pragma once

#include <stdint.h>

#include "common/tinycthread.h"
#include "common/util.h"

#include "core/blockchain.h"
#include "core/block.h"

#define RPC_DEFAULT_PORT 8332
#define RPC_MAX_CONNECTIONS 128
#define RPC_BUFFER_SIZE 8192

typedef struct rpc_server {
    int socket_fd;
    uint16_t port;
    char* username;
    char* password;
    int running;
    thrd_t server_thread;  // Changed from pthread_t to thrd_t
    mtx_t lock;           // Added mutex for thread safety
} rpc_server_t;

// Core RPC methods required for mining
typedef struct rpc_method {
    const char* name;
    char* (*handler)(const char* params);
} rpc_method_t;

// RPC server functions
int rpc_server_init(rpc_server_t* server, uint16_t port, const char* username, const char* password);
int rpc_server_start(rpc_server_t* server);
void rpc_server_stop(rpc_server_t* server);

// Mining RPC methods
char* rpc_getblocktemplate(const char* params);
char* rpc_submitblock(const char* params);
char* rpc_getwork(const char* params);
char* rpc_submitwork(const char* params);
char* rpc_getmininginfo(const char* params);
char* rpc_getnetworkhashps(const char* params);
char* rpc_getblockcount(const char* params);
char* rpc_getblockhash(const char* params);
char* rpc_getblock(const char* params);
