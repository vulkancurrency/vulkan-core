// Copyright (c) 2025, The Vulkan Developers.
//
// This file is part of Vulkan.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
//
// You should have received a copy of the MIT License
// along with Vulkan. If not, see <https://opensource.org/licenses/MIT>.

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
char* rpc_getnetworkinfo(const char* params);
char* rpc_getblockchaininfo(const char* params);
char* rpc_getindexinfo(const char* params);
char* rpc_getmempoolinfo(const char* params);
char* rpc_estimatesmartfee(const char* params);
char* rpc_getblockheader(const char* params);
char* rpc_getblockstats(const char* params);