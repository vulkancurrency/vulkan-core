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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <json-c/json.h>

#include "common/logger.h"
#include "common/tinycthread.h"

#include "crypto/cryptoutil.h"

#include "rpc_server.h"
#include "blockchain.h"
#include "block.h"
#include "mempool.h"
#include "pow.h"
#include "net.h"
#include "p2p.h"
#include "protocol.h"
#include "version.h"

static rpc_method_t rpc_methods[] = {
    {"getblocktemplate", rpc_getblocktemplate},
    {"submitblock", rpc_submitblock},
    {"getwork", rpc_getwork}, 
    {"submitwork", rpc_submitwork},
    {"getmininginfo", rpc_getmininginfo},
    {"getnetworkhashps", rpc_getnetworkhashps},
    {"getblockcount", rpc_getblockcount},
    {"getblockhash", rpc_getblockhash},
    {"getblock", rpc_getblock},
    {"getnetworkinfo", rpc_getnetworkinfo},
    {"getblockchaininfo", rpc_getblockchaininfo},
    {"getindexinfo", rpc_getindexinfo},
    {"getmempoolinfo", rpc_getmempoolinfo},
    {"estimatesmartfee", rpc_estimatesmartfee},
    {"getblockheader", rpc_getblockheader},
    {NULL, NULL}
};

static char* create_json_error(int code, const char* message) {
    struct json_object* response = json_object_new_object();
    struct json_object* error = json_object_new_object();
    
    json_object_object_add(error, "code", json_object_new_int(code));
    json_object_object_add(error, "message", json_object_new_string(message));
    
    json_object_object_add(response, "result", NULL);
    json_object_object_add(response, "error", error);
    json_object_object_add(response, "id", json_object_new_int(0));
    
    return strdup(json_object_to_json_string(response));
}

static int handle_client_thread(void* arg) {
    int client_fd = (intptr_t)arg;
    char buffer[RPC_BUFFER_SIZE];
    ssize_t bytes_read = read(client_fd, buffer, sizeof(buffer) - 1);
    
    if (bytes_read > 0) {
        buffer[bytes_read] = '\0';
        
        // Check if HTTP request contains basic auth
        char* auth = strstr(buffer, "Authorization: Basic ");
        if (!auth) {
            // Send 401 Unauthorized response
            const char* resp = "HTTP/1.1 401 Unauthorized\r\n"
                             "WWW-Authenticate: Basic realm=\"RPC Access\"\r\n"
                             "Content-Length: 0\r\n"
                             "Connection: close\r\n\r\n";
            write(client_fd, resp, strlen(resp));
            close(client_fd);
            return 0;
        }

        // Find the actual JSON-RPC request body after HTTP headers
        char* body = strstr(buffer, "\r\n\r\n");
        if (!body) {
            close(client_fd);
            return 0;
        }
        body += 4; // Skip \r\n\r\n

        // Parse the JSON-RPC request
        struct json_object* request = json_tokener_parse(body);
        if (!request) {
            char* error = create_json_error(-32700, "Parse error");
            char http_response[RPC_BUFFER_SIZE];
            snprintf(http_response, sizeof(http_response),
                "HTTP/1.1 200 OK\r\n"
                "Content-Type: application/json\r\n"
                "Content-Length: %zu\r\n"
                "Access-Control-Allow-Origin: *\r\n"
                "Access-Control-Allow-Methods: POST\r\n"
                "Access-Control-Allow-Headers: Authorization, Content-Type\r\n"
                "Connection: close\r\n"
                "\r\n"
                "%s", strlen(error), error);
            write(client_fd, http_response, strlen(http_response));
            free(error);
            close(client_fd);
            return 0;
        }

        // Extract method and id
        struct json_object* method_obj = NULL;
        struct json_object* id_obj = NULL;
        json_object_object_get_ex(request, "method", &method_obj);
        json_object_object_get_ex(request, "id", &id_obj);
        
        const char* method_name = method_obj ? json_object_get_string(method_obj) : NULL;
        int id = id_obj ? json_object_get_int(id_obj) : 1;

        // Find and execute the RPC method
        rpc_method_t* method = rpc_methods;
        while (method->name) {
            if (strcmp(method->name, method_name) == 0) {
                char* result = method->handler(NULL);
                
                // Always ensure we have a valid JSON response
                if (!result || strlen(result) == 0) {
                    struct json_object* response = json_object_new_object();
                    struct json_object* result_obj = json_object_new_object();
                    json_object_object_add(result_obj, "chain", json_object_new_string(parameters_get_use_testnet() ? "test" : "main"));
                    json_object_object_add(response, "result", result_obj);
                    json_object_object_add(response, "error", NULL);
                    json_object_object_add(response, "id", json_object_new_int(id));
                    result = strdup(json_object_to_json_string(response));
                    json_object_put(response);
                }
                
                char http_response[RPC_BUFFER_SIZE];
                snprintf(http_response, sizeof(http_response),
                    "HTTP/1.1 200 OK\r\n"
                    "Content-Type: application/json\r\n"
                    "Content-Length: %zu\r\n"
                    "Access-Control-Allow-Origin: *\r\n"
                    "Access-Control-Allow-Methods: POST\r\n"
                    "Access-Control-Allow-Headers: Authorization, Content-Type\r\n"
                    "Connection: close\r\n"
                    "\r\n"
                    "%s", strlen(result), result);
                write(client_fd, http_response, strlen(http_response));
                free(result);
                json_object_put(request);
                close(client_fd);
                return 0;
            }
            method++;
        }
        
        json_object_put(request);
    }
    
    close(client_fd);
    return 0;
}

static int server_thread_func(void* arg) {
    rpc_server_t* server = (rpc_server_t*)arg;
    
    while (server->running) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        
        int client_fd = accept(server->socket_fd, (struct sockaddr*)&client_addr, &client_len);
        if (client_fd < 0) continue;
        
        // Create thread using tinycthread
        thrd_t client_thread;
        if (thrd_create(&client_thread, handle_client_thread, (void*)(intptr_t)client_fd) == thrd_success) {
            thrd_detach(client_thread);
        } else {
            close(client_fd);
        }
    }
    
    return 0;
}

int rpc_server_init(rpc_server_t* server, uint16_t port, const char* username, const char* password) {
    server->port = port;
    server->username = strdup(username);
    server->password = strdup(password);
    server->running = 0;
    
    // Initialize mutex
    if (mtx_init(&server->lock, mtx_plain) != thrd_success) {
        return -1;
    }
    
    server->socket_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server->socket_fd < 0) {
        mtx_destroy(&server->lock);
        return -1;
    }
    
    int opt = 1;
    setsockopt(server->socket_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);
    
    if (bind(server->socket_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        return -1;
    }
    
    return 0;
}

int rpc_server_start(rpc_server_t* server) {
    server->running = 1;

    LOG_INFO("RPC Server started on port %d\n", server->port);
    
    if (listen(server->socket_fd, RPC_MAX_CONNECTIONS) < 0) {
        return -1;
    }
    
    // Create server thread using tinycthread
    if (thrd_create(&server->server_thread, server_thread_func, server) != thrd_success) {
        server->running = 0;
        return -1;
    }
    
    return 0;
}

void rpc_server_stop(rpc_server_t* server) {
    mtx_lock(&server->lock);
    server->running = 0;
    mtx_unlock(&server->lock);
    
    // Wait for server thread to finish
    thrd_join(server->server_thread, NULL);
    
    close(server->socket_fd);
    free(server->username);
    free(server->password);
    mtx_destroy(&server->lock);
}

// Implement the required RPC methods
char* rpc_getblocktemplate(const char* params) {
    block_t* template = create_new_block(); // Create new block template
    
    // Get latest block as parent
    block_t* parent = get_top_block();
    if (!parent) {
        return create_json_error(-5, "Failed to get parent block");
    }
    
    // Fill in block header
    template->version = get_block_version();
    memcpy(template->previous_hash, parent->hash, HASH_SIZE);
    template->timestamp = get_current_time();
    template->bits = get_next_work_required(parent->hash);
    
    // Add coinbase transaction
    transaction_t* coinbase = create_coinbase_transaction(get_block_reward(get_block_height(), 0));
    add_transaction_to_block(template, coinbase, template->transaction_count + 1); // transaction_count here = tx index
    
    // Add transactions from mempool
    add_transactions_from_mempool(template);
    
    // Create response
    struct json_object* response = json_object_new_object();
    struct json_object* result = json_object_new_object();
    
    json_object_object_add(result, "version", json_object_new_int(template->version));
    json_object_object_add(result, "previousblockhash", json_object_new_string(hex2bin(template->previous_hash, HASH_SIZE)));
    json_object_object_add(result, "timestamp", json_object_new_int(template->timestamp));
    json_object_object_add(result, "bits", json_object_new_int(template->bits));
    
    json_object_object_add(response, "result", result);
    json_object_object_add(response, "error", NULL);
    json_object_object_add(response, "id", json_object_new_int(1));
    
    free_block(template);
    return strdup(json_object_to_json_string(response));
}

char* rpc_submitblock(const char* params) {
    struct json_object* request = json_tokener_parse(params);
    const char* block_hex = json_object_get_string(request);
    
    // Decode hex block data
    size_t block_data_len;
    uint8_t* block_data = hex2bin(block_hex, &block_data_len);
    
    // Deserialize block
    block_t* block = NULL;
    buffer_t* buffer = buffer_init_data(0, block_data, block_data_len);
    buffer_iterator_t* iterator = buffer_iterator_init(buffer);
    
    if (deserialize_block(iterator, &block)) {
        free(block_data);
        buffer_iterator_free(iterator);
        buffer_free(buffer);
        return create_json_error(-5, "Block deserialization failed");
    }
    
    // Validate and insert block
    if (validate_and_insert_block(block)) {
        free(block_data);
        buffer_iterator_free(iterator);
        buffer_free(buffer);
        free_block(block);
        return create_json_error(-5, "Block validation failed");
    }
    
    free(block_data);
    buffer_iterator_free(iterator);
    buffer_free(buffer);
    free_block(block);
    
    struct json_object* response = json_object_new_object();
    json_object_object_add(response, "result", json_object_new_boolean(1));
    json_object_object_add(response, "error", NULL);
    json_object_object_add(response, "id", json_object_new_int(1));
    
    return strdup(json_object_to_json_string(response));
}

char* rpc_getwork(const char* params) {
    block_t* block = create_new_block();
    
    // Get latest block as parent
    block_t* parent = get_top_block();
    if (!parent) {
        free_block(block);
        return create_json_error(-5, "Failed to get parent block");
    }
    
    // Fill in block header
    block->version = get_block_version();
    memcpy(block->previous_hash, parent->hash, HASH_SIZE);
    block->timestamp = get_current_time();
    block->bits = get_next_work_required(parent->hash);
    
    // Add coinbase transaction
    transaction_t* coinbase = create_coinbase_transaction(get_block_reward(get_block_height(), 0));
    add_transaction_to_block(block, coinbase, block->transaction_count + 1);
    
    // Serialize block header
    buffer_t* buffer = buffer_init();
    serialize_block(buffer, &block);
    
    struct json_object* response = json_object_new_object();
    struct json_object* result = json_object_new_object();
    
    json_object_object_add(result, "data", json_object_new_string(hex2bin(buffer_get_data(buffer), buffer_get_size(buffer))));
    json_object_object_add(result, "target", json_object_new_string(hex2bin((uint8_t*)&block->bits, 4)));
    
    json_object_object_add(response, "result", result);
    json_object_object_add(response, "error", NULL);
    json_object_object_add(response, "id", json_object_new_int(1));
    
    buffer_free(buffer);
    free_block(block);
    
    return strdup(json_object_to_json_string(response));
}

char* rpc_submitwork(const char* params) {
    struct json_object* request = json_tokener_parse(params);
    const char* block_hex = json_object_get_string(request);
    
    // Decode block header
    size_t header_data_len;
    uint8_t* header_data = hex2bin(block_hex, &header_data_len);
    
    block_t block;
    buffer_t* buffer = buffer_init_data(0, header_data, header_data_len);
    buffer_iterator_t* iterator = buffer_iterator_init(buffer);
    
    if (deserialize_block(iterator, &block)) {
        free(header_data);
        buffer_iterator_free(iterator);
        buffer_free(buffer);
        return create_json_error(-5, "Block header deserialization failed");
    }
    
    // Validate proof of work
    uint32_t expected_difficulty = get_next_work_required(&block.hash);
    if (check_proof_of_work(&block, expected_difficulty) == 0) {
        free(header_data);
        buffer_iterator_free(iterator);
        buffer_free(buffer);
        return create_json_error(-5, "Invalid proof of work");
    }
    
    free(header_data);
    buffer_iterator_free(iterator);
    buffer_free(buffer);
    
    struct json_object* response = json_object_new_object();
    json_object_object_add(response, "result", json_object_new_boolean(1));
    json_object_object_add(response, "error", NULL);
    json_object_object_add(response, "id", json_object_new_int(1));
    
    return strdup(json_object_to_json_string(response));
}

char* rpc_getmininginfo(const char* params) {
    struct json_object* response = json_object_new_object();
    struct json_object* result = json_object_new_object();
    
    json_object_object_add(result, "blocks", json_object_new_int(get_block_height()));
    json_object_object_add(result, "currentblocksize", json_object_new_int(0)); // TODO: Implement
    json_object_object_add(result, "currentblocktx", json_object_new_int(0)); // TODO: Implement
    json_object_object_add(result, "difficulty", json_object_new_double(get_network_difficulty()));
    json_object_object_add(result, "networkhashps", json_object_new_double(get_network_hashrate()));
    
    json_object_object_add(response, "result", result);
    json_object_object_add(response, "error", NULL);
    json_object_object_add(response, "id", json_object_new_int(1));
    
    return strdup(json_object_to_json_string(response));
}

char* rpc_getnetworkhashps(const char* params) {
    double hashrate = get_network_hashrate();
    
    struct json_object* response = json_object_new_object();
    json_object_object_add(response, "result", json_object_new_double(hashrate));
    json_object_object_add(response, "error", NULL);
    json_object_object_add(response, "id", json_object_new_int(1));
    
    return strdup(json_object_to_json_string(response));
}

char* rpc_getblockcount(const char* params) {
    uint32_t height = get_block_height();
    
    struct json_object* response = json_object_new_object();
    json_object_object_add(response, "result", json_object_new_int(height));
    json_object_object_add(response, "error", NULL);
    json_object_object_add(response, "id", json_object_new_int(1));
    
    return strdup(json_object_to_json_string(response));
}

char* rpc_getblockhash(const char* params) {
    if (!params) {
        return create_json_error(-32602, "Invalid params - height required");
    }

    // Parse params array from JSON string
    struct json_object* params_obj = json_tokener_parse(params);
    if (!params_obj || !json_object_is_type(params_obj, json_type_array)) {
        if (params_obj) json_object_put(params_obj);
        return create_json_error(-32602, "Invalid params - must be JSON array");
    }

    // Get first array element (height)
    struct json_object* height_obj = json_object_array_get_idx(params_obj, 0);
    if (!height_obj || !json_object_is_type(height_obj, json_type_int)) {
        json_object_put(params_obj);
        return create_json_error(-32602, "Invalid params - height must be integer");
    }

    int height = json_object_get_int(height_obj);
    if (height < 0) {
        json_object_put(params_obj);
        return create_json_error(-32602, "Invalid params - height must be non-negative");
    }

    uint8_t* block_hash = get_block_hash_from_height(height);
    if (!block_hash) {
        json_object_put(params_obj);
        return create_json_error(-5, "Block height out of range");
    }

    // Convert hash to hex string
    char* hash_hex = bin2hex(block_hash, HASH_SIZE);
    free(block_hash);

    // Create response
    struct json_object* response = json_object_new_object();
    json_object_object_add(response, "result", json_object_new_string(hash_hex));
    json_object_object_add(response, "error", NULL);
    json_object_object_add(response, "id", json_object_new_int(1));

    free(hash_hex);
    json_object_put(params_obj);

    char* json_str = strdup(json_object_to_json_string(response));
    json_object_put(response);
    return json_str;
}

char* rpc_getblock(const char* params) {
    struct json_object* request = json_tokener_parse(params);
    const char* block_hash_hex = json_object_get_string(request);
    
    size_t hash_len;
    uint8_t* block_hash = hex2bin(block_hash_hex, &hash_len);
    
    block_t* block = get_block_from_hash(block_hash);
    free(block_hash);
    
    if (!block) {
        return create_json_error(-5, "Block not found");
    }
    
    struct json_object* response = json_object_new_object();
    struct json_object* result = json_object_new_object();
    
    // Fill in block details
    json_object_object_add(result, "hash", json_object_new_string(bin2hex(block->hash, HASH_SIZE)));
    json_object_object_add(result, "confirmations", json_object_new_int(get_blocks_since_block(block)));
    json_object_object_add(result, "size", json_object_new_int(get_block_size(block)));
    json_object_object_add(result, "height", json_object_new_int(get_block_height_from_block(block)));
    json_object_object_add(result, "version", json_object_new_int(block->version));
    json_object_object_add(result, "merkleroot", json_object_new_string(bin2hex(block->merkle_root, HASH_SIZE)));
    json_object_object_add(result, "time", json_object_new_int(block->timestamp));
    json_object_object_add(result, "nonce", json_object_new_int(block->nonce));
    json_object_object_add(result, "bits", json_object_new_string(bin2hex((uint8_t*)&block->bits, 4)));
    json_object_object_add(result, "difficulty", json_object_new_double(get_block_difficulty(block)));
    
    // Add transaction list
    struct json_object* tx_array = json_object_new_array();
    for (uint32_t i = 0; i < block->transaction_count; i++) {
        json_object_array_add(tx_array, json_object_new_string(bin2hex(block->transactions[i]->id, HASH_SIZE)));
    }
    json_object_object_add(result, "tx", tx_array);
    
    json_object_object_add(response, "result", result);
    json_object_object_add(response, "error", NULL);
    json_object_object_add(response, "id", json_object_new_int(1));
    
    free_block(block);
    return strdup(json_object_to_json_string(response));
}

char* rpc_getnetworkinfo(const char* params) {
    struct json_object* response = json_object_new_object();
    struct json_object* result = json_object_new_object();
    
    // Version info
    json_object_object_add(result, "chain", json_object_new_string(parameters_get_use_testnet() ? "test" : "main"));
    json_object_object_add(result, "version", json_object_new_int(atoi(APPLICATION_VERSION)));
    json_object_object_add(result, "subversion", json_object_new_string(APPLICATION_RELEASE_NAME));
    json_object_object_add(result, "protocolversion", json_object_new_int(APPLICATION_VERSION_PROTOCOL));
    
    // Network settings
    json_object_object_add(result, "blocks", json_object_new_int(get_block_height()));
    json_object_object_add(result, "testnet", json_object_new_boolean(parameters_get_use_testnet()));

    // Connection info  
    int num_connections = get_num_peers();
    json_object_object_add(result, "connections", json_object_new_int(num_connections));
    json_object_object_add(result, "networkactive", json_object_new_boolean(1));
    json_object_object_add(result, "connections_in", json_object_new_int(num_connections));
    json_object_object_add(result, "connections_out", json_object_new_int(0));

    // Other required fields
    json_object_object_add(result, "difficulty", json_object_new_double(get_network_difficulty()));
    json_object_object_add(result, "relayfee", json_object_new_double(0.00001));
    json_object_object_add(result, "warnings", json_object_new_string(""));

    json_object_object_add(response, "result", result);
    json_object_object_add(response, "error", NULL);
    json_object_object_add(response, "id", json_object_new_int(1));

    char* json_str = strdup(json_object_to_json_string(response));
    json_object_put(response);
    return json_str;
}

char* rpc_getblockchaininfo(const char* params) {
    struct json_object* response = json_object_new_object();
    struct json_object* result = json_object_new_object();
    
    // Chain info
    json_object_object_add(result, "chain", json_object_new_string(parameters_get_use_testnet() ? "test" : "main"));
    json_object_object_add(result, "blocks", json_object_new_int(get_block_height()));
    json_object_object_add(result, "headers", json_object_new_int(get_block_height()));
    
    // Best block info
    block_t* top_block = get_top_block();
    if (top_block) {
        char* best_hash = bin2hex(top_block->hash, HASH_SIZE);
        json_object_object_add(result, "bestblockhash", json_object_new_string(best_hash));
        free(best_hash);
        free_block(top_block);
    } else {
        json_object_object_add(result, "bestblockhash", json_object_new_string(""));
    }
    
    // Difficulty
    json_object_object_add(result, "difficulty", json_object_new_double(get_network_difficulty()));
    json_object_object_add(result, "mediantime", json_object_new_int(get_current_time()));
    
    // Verification status
    json_object_object_add(result, "verificationprogress", json_object_new_double(1.0));
    json_object_object_add(result, "initialblockdownload", json_object_new_boolean(0));
    
    // Chain statistics
    json_object_object_add(result, "chainwork", json_object_new_string(""));
    json_object_object_add(result, "size_on_disk", json_object_new_int64(0));
    json_object_object_add(result, "pruned", json_object_new_boolean(0));
    
    // Add warnings if any
    json_object_object_add(result, "warnings", json_object_new_string(""));

    json_object_object_add(response, "result", result);
    json_object_object_add(response, "error", NULL);
    json_object_object_add(response, "id", json_object_new_int(1));

    char* json_str = strdup(json_object_to_json_string(response));
    json_object_put(response);
    return json_str;
}

char* rpc_getindexinfo(const char* params) {
    struct json_object* response = json_object_new_object();
    struct json_object* result = json_object_new_object();
    
    // Create txindex info
    struct json_object* txindex = json_object_new_object();
    json_object_object_add(txindex, "synced", json_object_new_boolean(1));
    json_object_object_add(txindex, "best_block_height", json_object_new_int(get_block_height()));
    
    // Add indexes info
    json_object_object_add(result, "txindex", txindex);
    
    // Create default response
    json_object_object_add(response, "result", result);
    json_object_object_add(response, "error", NULL);
    json_object_object_add(response, "id", json_object_new_int(1));

    char* json_str = strdup(json_object_to_json_string(response));
    json_object_put(response);
    return json_str;
}

char* rpc_getmempoolinfo(const char* params) {
    struct json_object* response = json_object_new_object();
    struct json_object* result = json_object_new_object();
    
    // Get mempool info
    json_object_object_add(result, "size", json_object_new_int(get_mempool_size()));
    json_object_object_add(result, "bytes", json_object_new_int64(get_mempool_bytes()));
    json_object_object_add(result, "usage", json_object_new_int64(get_mempool_usage()));
    json_object_object_add(result, "maxmempool", json_object_new_int64(MAX_MEMPOOL_SIZE));
    json_object_object_add(result, "mempoolminfee", json_object_new_double(0.00001)); // 1 sat/byte minimum
    json_object_object_add(result, "minrelaytxfee", json_object_new_double(0.00001));
    
    json_object_object_add(response, "result", result);
    json_object_object_add(response, "error", NULL);
    json_object_object_add(response, "id", json_object_new_int(1));

    char* json_str = strdup(json_object_to_json_string(response));
    json_object_put(response);
    return json_str;
}

char* rpc_estimatesmartfee(const char* params) {
    struct json_object* response = json_object_new_object();
    struct json_object* result = json_object_new_object();
    
    // For now return conservative fixed fee estimate
    json_object_object_add(result, "feerate", json_object_new_double(0.00001)); // 1 sat/byte
    json_object_object_add(result, "blocks", json_object_new_int(6));
    
    json_object_object_add(response, "result", result);
    json_object_object_add(response, "error", NULL);
    json_object_object_add(response, "id", json_object_new_int(1));

    char* json_str = strdup(json_object_to_json_string(response));
    json_object_put(response);
    return json_str;
}

char* rpc_getblockheader(const char* params) {
    if (!params) {
        return create_json_error(-32602, "Invalid params - block hash required");
    }

    // Parse params array from JSON string
    struct json_object* params_obj = json_tokener_parse(params);
    if (!params_obj || !json_object_is_type(params_obj, json_type_array)) {
        if (params_obj) json_object_put(params_obj);
        return create_json_error(-32602, "Invalid params - must be JSON array");
    }

    // Get block hash from params
    struct json_object* hash_obj = json_object_array_get_idx(params_obj, 0);
    if (!hash_obj || !json_object_is_type(hash_obj, json_type_string)) {
        json_object_put(params_obj);
        return create_json_error(-32602, "Invalid params - block hash must be string");
    }

    const char* block_hash_hex = json_object_get_string(hash_obj);
    size_t hash_len;
    uint8_t* block_hash = hex2bin(block_hash_hex, &hash_len);
    
    block_t* block = get_block_from_hash(block_hash);
    free(block_hash);
    
    if (!block) {
        json_object_put(params_obj);
        return create_json_error(-5, "Block not found");
    }

    struct json_object* response = json_object_new_object();
    struct json_object* result = json_object_new_object();
    
    // Only include header info
    json_object_object_add(result, "hash", json_object_new_string(bin2hex(block->hash, HASH_SIZE)));
    json_object_object_add(result, "confirmations", json_object_new_int(get_blocks_since_block(block)));
    json_object_object_add(result, "height", json_object_new_int(get_block_height_from_block(block)));
    json_object_object_add(result, "version", json_object_new_int(block->version));
    json_object_object_add(result, "merkleroot", json_object_new_string(bin2hex(block->merkle_root, HASH_SIZE)));
    json_object_object_add(result, "time", json_object_new_int(block->timestamp));
    json_object_object_add(result, "nonce", json_object_new_int(block->nonce));
    json_object_object_add(result, "bits", json_object_new_string(bin2hex((uint8_t*)&block->bits, 4)));
    json_object_object_add(result, "difficulty", json_object_new_double(get_block_difficulty(block)));
    
    if (block->previous_hash) {
        json_object_object_add(result, "previousblockhash", 
            json_object_new_string(bin2hex(block->previous_hash, HASH_SIZE)));
    }

    // Get next block hash if it exists
    uint32_t current_height = get_block_height_from_block(block);
    block_t* next_block = get_block_from_height(current_height + 1);
    if (next_block) {
        json_object_object_add(result, "nextblockhash",
            json_object_new_string(bin2hex(next_block->hash, HASH_SIZE)));
        free_block(next_block);
    }
    
    json_object_object_add(response, "result", result);
    json_object_object_add(response, "error", NULL);
    json_object_object_add(response, "id", json_object_new_int(1));
    
    free_block(block);
    json_object_put(params_obj);

    char* json_str = strdup(json_object_to_json_string(response));
    json_object_put(response);
    return json_str;
}