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

static rpc_method_t g_rpc_methods[] = {
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
    {"getblockstats", rpc_getblockstats},
    {"getrawtransaction", rpc_getrawtransaction},
    {"gettxoutsetinfo", rpc_gettxoutsetinfo},
    {"getdeploymentinfo", rpc_getdeploymentinfo},
    {"uptime", rpc_uptime},
    {"getnettotals", rpc_getnettotals}, 
    {"getrawmempool", rpc_getrawmempool},
    {"getmempoolfeeinfo", rpc_getmempoolfeeinfo},
    {"getpeerinfo", rpc_getpeerinfo},
    {"getchaintxstats", rpc_getchaintxstats},
    {"sendrawtransaction", rpc_sendrawtransaction},
    {"createrawtransaction", rpc_createrawtransaction},
    {"decoderawtransaction", rpc_decoderawtransaction}, 
    {"testmempoolaccept", rpc_testmempoolaccept},
    {"gettxout", rpc_gettxout},
    {"pruneblockchain", rpc_pruneblockchain},
    {"gettxoutproof", rpc_gettxoutproof},
    {"verifytxoutproof", rpc_verifytxoutproof},
    {"verifychain", rpc_verifychain},
    {"invalidateblock", rpc_invalidateblock},
    {"reconsiderblock", rpc_reconsiderblock},
    {"waitfornewblock", rpc_waitfornewblock},
    {"waitforblock", rpc_waitforblock},
    {"setnetworkactive", rpc_setnetworkactive},
    {"addnode", rpc_addnode},
    {"disconnectnode", rpc_disconnectnode},
    {"getaddednodeinfo", rpc_getaddednodeinfo},
    {"setban", rpc_setban},
    {"listbanned", rpc_listbanned},
    {"clearbanned", rpc_clearbanned},
    {"ping", rpc_ping},
    {NULL, NULL}
};

static time_t g_start_time = 0;

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
        
        // Add OPTIONS request handling for CORS preflight
        if (strncmp(buffer, "OPTIONS", 7) == 0) {
            const char* resp = "HTTP/1.1 200 OK\r\n"
                             "Access-Control-Allow-Origin: *\r\n"
                             "Access-Control-Allow-Methods: POST, OPTIONS\r\n"
                             "Access-Control-Allow-Headers: Content-Type, Authorization, X-CSRF-Token\r\n"
                             "Access-Control-Allow-Credentials: true\r\n"
                             "Content-Length: 0\r\n"
                             "Connection: close\r\n\r\n";
            write(client_fd, resp, strlen(resp));
            close(client_fd);
            return 0;
        }

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

        // Extract method, params and id
        struct json_object* method_obj = NULL;
        struct json_object* params_obj = NULL;
        struct json_object* id_obj = NULL;
        json_object_object_get_ex(request, "method", &method_obj);
        json_object_object_get_ex(request, "params", &params_obj);
        json_object_object_get_ex(request, "id", &id_obj);
        
        const char* method_name = method_obj ? json_object_get_string(method_obj) : NULL;
        const char* params = params_obj ? json_object_to_json_string(params_obj) : NULL;
        int id = id_obj ? json_object_get_int(id_obj) : 1;

        // Find and execute the RPC method
        rpc_method_t* method = g_rpc_methods;
        while (method->name) {
            if (strcmp(method->name, method_name) == 0) {
                LOG_DEBUG("RPC call: %s", method_name);;
                char* result = method->handler(params);
                
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
                    "Access-Control-Allow-Methods: POST, OPTIONS\r\n"
                    "Access-Control-Allow-Headers: Content-Type, Authorization, X-CSRF-Token\r\n"
                    "Access-Control-Allow-Credentials: true\r\n"
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
    // Parse params first
    if (!params) {
        return create_json_error(-32602, "Invalid params - rules required");
    }

    struct json_object* params_obj = json_tokener_parse(params);
    if (!params_obj || !json_object_is_type(params_obj, json_type_array)) {
        if (params_obj) json_object_put(params_obj);
        return create_json_error(-32602, "Invalid params - must be JSON array");
    }

    // Get template rules
    struct json_object* rules_obj = json_object_array_get_idx(params_obj, 0);
    if (!rules_obj || !json_object_is_type(rules_obj, json_type_object)) {
        json_object_put(params_obj);
        return create_json_error(-32602, "Invalid params - first argument must be object");
    }

    block_t* template = create_new_block();
    
    // Get latest block as parent
    block_t* parent = get_top_block();
    if (!parent) {
        json_object_put(params_obj);
        free_block(template);
        return create_json_error(-5, "Failed to get parent block");
    }
    
    // Fill in block header
    template->version = get_block_version();
    memcpy(template->previous_hash, parent->hash, HASH_SIZE);
    template->timestamp = get_current_time();
    template->bits = get_next_work_required(parent->hash);
    
    // Add coinbase transaction
    uint64_t reward = get_block_reward(get_block_height(), 0);
    transaction_t* coinbase = create_coinbase_transaction(reward);
    if (add_transaction_to_block(template, coinbase, 0)) { // coinbase tx is always first
        json_object_put(params_obj);
        free_block(template);
        free_block(parent);
        return create_json_error(-5, "Failed to add coinbase transaction");
    }
    
    // Add transactions from mempool
    add_transactions_from_mempool(template);
    
    // Create response with required fields
    struct json_object* response = json_object_new_object();
    struct json_object* result = json_object_new_object();
    
    // Add current height first - this is required by btc-rpc-explorer
    uint32_t current_height = get_block_height();
    json_object_object_add(result, "height", json_object_new_int(current_height + 1));
    json_object_object_add(result, "previousheight", json_object_new_int(current_height));
    
    // Add all required fields for block template
    json_object_object_add(result, "capabilities", json_object_new_array());
    json_object_object_add(result, "version", json_object_new_int(template->version));
    json_object_object_add(result, "rules", json_object_new_array());
    json_object_object_add(result, "vbavailable", json_object_new_object());
    json_object_object_add(result, "vbrequired", json_object_new_int(0));
    json_object_object_add(result, "previousblockhash", 
        json_object_new_string(bin2hex(template->previous_hash, HASH_SIZE)));

    // Add required height info and difficulty adjustment fields
    json_object_object_add(result, "currentheight", json_object_new_int(current_height));
    
    // Add difficulty adjustment info
    json_object_object_add(result, "target_timespan", json_object_new_int(POW_TARGET_TIMESPAN));
    json_object_object_add(result, "target_spacing", json_object_new_int(POW_TARGET_SPACING));
    json_object_object_add(result, "difficulty_adjustment_interval", 
        json_object_new_int(parameters_get_difficulty_adjustment_interval()));
    json_object_object_add(result, "difficulty", json_object_new_double(get_network_difficulty()));

    // Add chainwork
    json_object_object_add(result, "chainwork", 
        json_object_new_string("0000000000000000000000000000000000000000000000000000000000020000"));

    // Required fields for block template
    json_object_object_add(result, "capabilities", json_object_new_array());
    json_object_object_add(result, "version", json_object_new_int(template->version));
    json_object_object_add(result, "rules", json_object_new_array());
    json_object_object_add(result, "vbavailable", json_object_new_object());
    json_object_object_add(result, "vbrequired", json_object_new_int(0));
    json_object_object_add(result, "previousblockhash", 
        json_object_new_string(bin2hex(template->previous_hash, HASH_SIZE)));
    
    // Transaction data
    struct json_object* transactions = json_object_new_array();
    for (uint32_t i = 1; i < template->transaction_count; i++) {
        struct json_object* tx_data = json_object_new_object();
        transaction_t* tx = template->transactions[i];
        
        json_object_object_add(tx_data, "data", 
            json_object_new_string(bin2hex((uint8_t*)tx->id, HASH_SIZE)));
        json_object_object_add(tx_data, "txid",
            json_object_new_string(bin2hex(tx->id, HASH_SIZE)));
        json_object_object_add(tx_data, "fee", 
            json_object_new_int(calculate_transaction_fee(tx)));
            
        json_object_array_add(transactions, tx_data);
    }
    json_object_object_add(result, "transactions", transactions);
    
    // Mining related fields
    json_object_object_add(result, "coinbaseaux", json_object_new_object());
    json_object_object_add(result, "coinbasevalue", json_object_new_int64(reward));
    json_object_object_add(result, "longpollid", 
        json_object_new_string(bin2hex(template->previous_hash, HASH_SIZE)));
    json_object_object_add(result, "target", 
        json_object_new_string(bin2hex((uint8_t*)&template->bits, 4)));
    json_object_object_add(result, "mintime", json_object_new_int(get_current_time() - MAX_FUTURE_BLOCK_TIME));
    json_object_object_add(result, "mutable", json_object_new_array());
    json_object_object_add(result, "noncerange", 
        json_object_new_string("00000000ffffffff"));
    json_object_object_add(result, "sigoplimit", json_object_new_int(MAX_BLOCK_SIZE/50));
    json_object_object_add(result, "sizelimit", json_object_new_int(MAX_BLOCK_SIZE));
    json_object_object_add(result, "weightlimit", json_object_new_int(MAX_BLOCK_SIZE));
    json_object_object_add(result, "curtime", json_object_new_int(template->timestamp));
    json_object_object_add(result, "bits", 
        json_object_new_string(bin2hex((uint8_t*)&template->bits, 4)));
    json_object_object_add(result, "height", json_object_new_int(get_block_height() + 1));
    
    json_object_object_add(response, "result", result);
    json_object_object_add(response, "error", NULL);
    json_object_object_add(response, "id", json_object_new_int(1));
    
    free_block(template);
    free_block(parent);
    json_object_put(params_obj);
    
    char* json_str = strdup(json_object_to_json_string(response));
    json_object_put(response);
    return json_str;
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
    add_transaction_to_block(block, coinbase, 0); // Coinbase transaction is always first
    
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
    
    // Fill in block details
    uint32_t height = get_block_height_from_block(block);
    
    json_object_object_add(result, "hash", json_object_new_string(bin2hex(block->hash, HASH_SIZE)));
    json_object_object_add(result, "confirmations", json_object_new_int(get_blocks_since_block(block)));
    json_object_object_add(result, "size", json_object_new_int(get_block_size(block)));
    json_object_object_add(result, "height", json_object_new_int(height));
    json_object_object_add(result, "version", json_object_new_int(block->version));
    json_object_object_add(result, "versionHex", json_object_new_string("00000001"));
    json_object_object_add(result, "merkleroot", json_object_new_string(bin2hex(block->merkle_root, HASH_SIZE)));
    json_object_object_add(result, "time", json_object_new_int(block->timestamp));
    json_object_object_add(result, "mediantime", json_object_new_int(block->timestamp));
    json_object_object_add(result, "nonce", json_object_new_int(block->nonce));
    json_object_object_add(result, "bits", json_object_new_string(bin2hex((uint8_t*)&block->bits, 4)));
    json_object_object_add(result, "difficulty", json_object_new_double(get_block_difficulty(block)));
    json_object_object_add(result, "chainwork", json_object_new_string("0000000000000000000000000000000000000000000000000000000000000000"));
    
    if (block->previous_hash) {
        json_object_object_add(result, "previousblockhash",
            json_object_new_string(bin2hex(block->previous_hash, HASH_SIZE)));
    }

    // Get next block hash if it exists
    block_t* next_block = get_block_from_height(height + 1);
    if (next_block) {
        json_object_object_add(result, "nextblockhash",
            json_object_new_string(bin2hex(next_block->hash, HASH_SIZE)));
        free_block(next_block);
    }

    // Add transaction list
    struct json_object* tx_array = json_object_new_array();
    if (block->transactions) {
        for (uint32_t i = 0; i < block->transaction_count; i++) {
            transaction_t* tx = block->transactions[i];
            if (tx && tx->id) {
                json_object_array_add(tx_array, json_object_new_string(bin2hex(tx->id, HASH_SIZE)));
            }
        }
    }
    json_object_object_add(result, "tx", tx_array);
    json_object_object_add(result, "nTx", json_object_new_int(block->transaction_count));
    
    json_object_object_add(response, "result", result);
    json_object_object_add(response, "error", NULL);
    json_object_object_add(response, "id", json_object_new_int(1));
    
    free_block(block);
    json_object_put(params_obj);

    char* json_str = strdup(json_object_to_json_string(response));
    json_object_put(response);
    return json_str;
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
    
    // Always include height field first
    uint32_t current_height = get_block_height();
    time_t current_time = get_current_time();
    
    // Required chain info
    json_object_object_add(result, "chain", json_object_new_string(parameters_get_use_testnet() ? "test" : "main"));
    json_object_object_add(result, "blocks", json_object_new_int(current_height));
    json_object_object_add(result, "headers", json_object_new_int(current_height));
    json_object_object_add(result, "height", json_object_new_int(current_height));
    json_object_object_add(result, "bestblockhash", json_object_new_string(""));
    json_object_object_add(result, "difficulty", json_object_new_double(get_network_difficulty()));
    json_object_object_add(result, "mediantime", json_object_new_int64(current_time));
    json_object_object_add(result, "verificationprogress", json_object_new_double(1.0));
    json_object_object_add(result, "initialblockdownload", json_object_new_boolean(0));
    json_object_object_add(result, "size_on_disk", json_object_new_int64(0));
    json_object_object_add(result, "pruned", json_object_new_boolean(0));
    
    // Get best block info
    block_t* current_block = get_top_block();
    if (current_block) {
        char* best_hash = bin2hex(current_block->hash, HASH_SIZE);
        json_object_object_add(result, "bestblockhash", json_object_new_string(best_hash));
        json_object_object_add(result, "mediantime", json_object_new_int64(current_block->timestamp));
        free(best_hash);
        free_block(current_block);
    }
    
    // Add chainwork (required for progress calculation)
    json_object_object_add(result, "chainwork", 
        json_object_new_string("0000000000000000000000000000000000000000000000000000000100000000"));
    
    // Add warnings
    json_object_object_add(result, "warnings", json_object_new_string(""));
    
    // Add softforks info (required by explorer)
    struct json_object* softforks = json_object_new_object();
    
    // Add BIP34 softfork info
    struct json_object* bip34 = json_object_new_object();
    json_object_object_add(bip34, "type", json_object_new_string("buried"));
    json_object_object_add(bip34, "active", json_object_new_boolean(0));
    json_object_object_add(bip34, "height", json_object_new_int(0));
    json_object_object_add(softforks, "bip34", bip34);
    
    json_object_object_add(result, "softforks", softforks);
    
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
    json_object_object_add(result, "height", json_object_new_int(get_block_height() + 1));
    
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

char* rpc_getblockstats(const char* params) {
    if (!params) {
        return create_json_error(-32602, "Invalid params - block height/hash required");
    }

    struct json_object* params_obj = json_tokener_parse(params);
    if (!params_obj || !json_object_is_type(params_obj, json_type_array)) {
        if (params_obj) json_object_put(params_obj);
        return create_json_error(-32602, "Invalid params - must be JSON array");
    }

    // Get height/hash parameter
    struct json_object* height_obj = json_object_array_get_idx(params_obj, 0);
    if (!height_obj) {
        json_object_put(params_obj);
        return create_json_error(-32602, "Invalid params - height/hash parameter required");
    }

    // Get the block
    block_t* block = NULL;
    if (json_object_is_type(height_obj, json_type_int)) {
        int height = json_object_get_int(height_obj);
        block = get_block_from_height(height);
    } else if (json_object_is_type(height_obj, json_type_string)) {
        const char* hash = json_object_get_string(height_obj);
        size_t hash_len;
        uint8_t* block_hash = hex2bin(hash, &hash_len);
        if (block_hash) {
            block = get_block_from_hash(block_hash);
            free(block_hash);
        }
    }

    if (!block) {
        json_object_put(params_obj);
        return create_json_error(-32602, "Block not found");
    }

    // Create response
    struct json_object* response = json_object_new_object();
    struct json_object* result = json_object_new_object();

    // Block stats
    json_object_object_add(result, "height", json_object_new_int(get_block_height_from_block(block)));
    json_object_object_add(result, "hash", json_object_new_string(bin2hex(block->hash, HASH_SIZE)));
    json_object_object_add(result, "time", json_object_new_int(block->timestamp));
    json_object_object_add(result, "nonce", json_object_new_int(block->nonce));
    json_object_object_add(result, "version", json_object_new_int(block->version));
    json_object_object_add(result, "merkleroot", json_object_new_string(bin2hex(block->merkle_root, HASH_SIZE)));
    json_object_object_add(result, "bits", json_object_new_string(bin2hex((uint8_t*)&block->bits, 4)));
    
    // Transaction stats
    json_object_object_add(result, "txs", json_object_new_int(block->transaction_count));
    
    uint64_t total_out = 0;
    uint64_t total_size = 0;
    uint64_t total_weight = 0;
    
    for (uint32_t i = 0; i < block->transaction_count; i++) {
        transaction_t* tx = block->transactions[i];
        for (uint32_t j = 0; j < tx->txout_count; j++) {
            total_out += tx->txouts[j]->amount;
        }
        total_size += get_tx_header_size(tx);
        total_weight += get_tx_header_size(tx) * 4; // Simplified weight calculation
    }

    json_object_object_add(result, "total_out", json_object_new_int64(total_out));
    json_object_object_add(result, "total_size", json_object_new_int64(total_size));
    json_object_object_add(result, "total_weight", json_object_new_int64(total_weight));
    json_object_object_add(result, "avgfee", json_object_new_int64(block->transaction_count > 1 ? total_out / (block->transaction_count - 1) : 0));
    json_object_object_add(result, "avgfeerate", json_object_new_int64(total_size > 0 ? total_out / total_size : 0));

    json_object_object_add(response, "result", result); 
    json_object_object_add(response, "error", NULL);
    json_object_object_add(response, "id", json_object_new_int(1));

    free_block(block);
    json_object_put(params_obj);

    char* json_str = strdup(json_object_to_json_string(response));
    json_object_put(response);
    return json_str;
}

char* rpc_getrawtransaction(const char* params) {
    if (!params) {
        return create_json_error(-32602, "Invalid params");
    }

    struct json_object* params_obj = json_tokener_parse(params);
    if (!params_obj || !json_object_is_type(params_obj, json_type_array)) {
        if (params_obj) json_object_put(params_obj);
        return create_json_error(-32602, "Invalid params - must be JSON array");
    }

    // Get txid parameter
    struct json_object* txid_obj = json_object_array_get_idx(params_obj, 0);
    if (!txid_obj || !json_object_is_type(txid_obj, json_type_string)) {
        json_object_put(params_obj);
        return create_json_error(-32602, "Invalid txid parameter");
    }

    // Get verbose flag (optional)
    int verbose = 0;
    struct json_object* verbose_obj = json_object_array_get_idx(params_obj, 1);
    if (verbose_obj && json_object_is_type(verbose_obj, json_type_int)) {
        verbose = json_object_get_int(verbose_obj);
    }

    const char* txid_str = json_object_get_string(txid_obj);
    size_t hash_len;
    uint8_t* tx_hash = hex2bin(txid_str, &hash_len);
    if (!tx_hash || hash_len != HASH_SIZE) {
        json_object_put(params_obj);
        if (tx_hash) free(tx_hash);
        return create_json_error(-32602, "Invalid transaction hash");
    }

    // Find block containing transaction
    block_t* block = get_block_from_tx_id(tx_hash);
    if (!block) {
        free(tx_hash);
        json_object_put(params_obj);
        return create_json_error(-5, "Transaction not found");
    }

    // Find transaction in block
    transaction_t* tx = NULL;
    for (uint32_t i = 0; i < block->transaction_count; i++) {
        if (memcmp(block->transactions[i]->id, tx_hash, HASH_SIZE) == 0) {
            tx = block->transactions[i];
            break;
        }
    }

    free(tx_hash);

    if (!tx) {
        free_block(block);
        json_object_put(params_obj);
        return create_json_error(-5, "Transaction not found in block");
    }

    struct json_object* response = json_object_new_object();
    struct json_object* result;

    if (verbose) {
        // Verbose output - detailed transaction info
        result = json_object_new_object();
        
        // Transaction hash
        char* txid = bin2hex(tx->id, HASH_SIZE);
        json_object_object_add(result, "txid", json_object_new_string(txid));
        free(txid);

        // Block info
        char* block_hash = bin2hex(block->hash, HASH_SIZE);
        json_object_object_add(result, "blockhash", json_object_new_string(block_hash));
        free(block_hash);
        
        json_object_object_add(result, "confirmations", 
            json_object_new_int(get_blocks_since_block(block)));
        json_object_object_add(result, "time", json_object_new_int(block->timestamp));
        json_object_object_add(result, "blocktime", json_object_new_int(block->timestamp));
        json_object_object_add(result, "size", json_object_new_int(get_tx_header_size(tx)));

        // Transaction details
        json_object_object_add(result, "version", json_object_new_int(tx->version));
        
        // Inputs array
        struct json_object* vin = json_object_new_array();
        for (uint32_t i = 0; i < tx->txin_count; i++) {
            struct json_object* input = json_object_new_object();
            input_transaction_t* txin = tx->txins[i];
            
            if (is_coinbase_tx(tx)) {
                json_object_object_add(input, "coinbase", json_object_new_string(""));
            } else {
                char* prev_txid = bin2hex(txin->transaction, HASH_SIZE);
                json_object_object_add(input, "txid", json_object_new_string(prev_txid));
                free(prev_txid);
                json_object_object_add(input, "vout", json_object_new_int(txin->txout_index));
            }
            
            // Add empty sequence and scriptSig fields
            struct json_object* script_sig = json_object_new_object();
            json_object_object_add(script_sig, "asm", json_object_new_string(""));
            json_object_object_add(script_sig, "hex", json_object_new_string(""));
            json_object_object_add(input, "scriptSig", script_sig);
            json_object_object_add(input, "sequence", json_object_new_int64(0xffffffff));
            
            json_object_array_add(vin, input);
        }
        json_object_object_add(result, "vin", vin);

        // Outputs array 
        struct json_object* vout = json_object_new_array();
        for (uint32_t i = 0; i < tx->txout_count; i++) {
            struct json_object* output = json_object_new_object();
            output_transaction_t* txout = tx->txouts[i];
            
            // Format value properly as string with 8 decimal places
            char value_str[32];
            snprintf(value_str, sizeof(value_str), "%.8f", (double)txout->amount / COIN);
            json_object_object_add(output, "value", json_object_new_string(value_str));
            json_object_object_add(output, "n", json_object_new_int(i));
            
            struct json_object* script_pub_key = json_object_new_object();
            if (txout->address) {
                char* addr = bin2hex(txout->address, ADDRESS_SIZE);
                struct json_object* addresses = json_object_new_array();
                json_object_array_add(addresses, json_object_new_string(addr));
                json_object_object_add(script_pub_key, "addresses", addresses);
                free(addr);
            }
            
            // Required scriptPubKey fields
            json_object_object_add(script_pub_key, "asm", json_object_new_string(""));
            json_object_object_add(script_pub_key, "hex", json_object_new_string(""));
            json_object_object_add(script_pub_key, "type", json_object_new_string("pubkeyhash"));
            json_object_object_add(script_pub_key, "reqSigs", json_object_new_int(1));
            
            json_object_object_add(output, "scriptPubKey", script_pub_key);
            json_object_array_add(vout, output);
        }
        json_object_object_add(result, "vout", vout);
        
        // Add hex field for raw transaction
        buffer_t* buffer = buffer_init();
        serialize_transaction(buffer, tx);
        char* tx_hex = bin2hex(buffer_get_data(buffer), buffer_get_size(buffer));
        json_object_object_add(result, "hex", json_object_new_string(tx_hex));
        free(tx_hex);
        buffer_free(buffer);
    } else {
        // Non-verbose - just raw transaction hex
        buffer_t* buffer = buffer_init();
        serialize_transaction(buffer, tx);
        
        char* tx_hex = bin2hex(buffer_get_data(buffer), buffer_get_size(buffer));
        result = json_object_new_string(tx_hex);
        
        free(tx_hex);
        buffer_free(buffer);
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

char* rpc_gettxoutsetinfo(const char* params) {
    struct json_object* response = json_object_new_object();
    struct json_object* result = json_object_new_object();
    
    // Required fields for txoutset info
    json_object_object_add(result, "height", json_object_new_int(get_block_height()));
    json_object_object_add(result, "bestblock", json_object_new_string(bin2hex(get_current_block_hash(), HASH_SIZE)));
    
    // Count transactions and total amount
    uint64_t total_amount = 0;
    uint64_t transactions = 0;
    uint64_t txouts = 0;
    
    // Iterate through all blocks
    uint32_t height = get_block_height();
    for (uint32_t i = 0; i <= height; i++) {
        block_t* block = get_block_from_height(i);
        if (!block) continue;
        
        for (uint32_t j = 0; j < block->transaction_count; j++) {
            transaction_t* tx = block->transactions[j];
            transactions++;
            
            for (uint32_t k = 0; k < tx->txout_count; k++) {
                output_transaction_t* txout = tx->txouts[k];
                if (txout) {
                    total_amount += txout->amount;
                    txouts++;
                }
            }
        }
        free_block(block);
    }
    
    // Add statistics
    json_object_object_add(result, "transactions", json_object_new_int64(transactions));
    json_object_object_add(result, "txouts", json_object_new_int64(txouts));
    json_object_object_add(result, "total_amount", json_object_new_double((double)total_amount / COIN));
    
    // Add to response
    json_object_object_add(response, "result", result);
    json_object_object_add(response, "error", NULL); 
    json_object_object_add(response, "id", json_object_new_int(1));
    
    char* json_str = strdup(json_object_to_json_string(response));
    json_object_put(response);
    return json_str;
}

char* rpc_getdeploymentinfo(const char* params) {
    struct json_object* response = json_object_new_object();
    struct json_object* result = json_object_new_object();
    
    // Create deployments info (empty since we don't have any active deployments)
    struct json_object* deployments = json_object_new_object();
    
    json_object_object_add(result, "deployments", deployments);
    json_object_object_add(response, "result", result);
    json_object_object_add(response, "error", NULL);
    json_object_object_add(response, "id", json_object_new_int(1));
    
    char* json_str = strdup(json_object_to_json_string(response));
    json_object_put(response);
    return json_str;
}

char* rpc_uptime(const char* params) {
    struct json_object* response = json_object_new_object();
    
    // Calculate uptime in seconds
    time_t uptime = 0;
    if (g_start_time == 0) {
        g_start_time = time(NULL);
    } else {
        uptime = time(NULL) - g_start_time;
    }
    
    json_object_object_add(response, "result", json_object_new_int64(uptime));
    json_object_object_add(response, "error", NULL);
    json_object_object_add(response, "id", json_object_new_int(1));
    
    char* json_str = strdup(json_object_to_json_string(response));
    json_object_put(response);
    return json_str;
}

char* rpc_getnettotals(const char* params) {
    struct json_object* response = json_object_new_object();
    struct json_object* result = json_object_new_object();
    
    // Network statistics
    json_object_object_add(result, "totalbytesrecv", json_object_new_int64(0));
    json_object_object_add(result, "totalbytessent", json_object_new_int64(0));
    json_object_object_add(result, "timemillis", json_object_new_int64(time(NULL) * 1000));
    
    json_object_object_add(response, "result", result);
    json_object_object_add(response, "error", NULL);
    json_object_object_add(response, "id", json_object_new_int(1));
    
    char* json_str = strdup(json_object_to_json_string(response));
    json_object_put(response);
    return json_str;
}

char* rpc_getrawmempool(const char* params) {
    struct json_object* response = json_object_new_object();
    struct json_object* result = json_object_new_object();

    // Get all transactions from mempool
    transaction_t** mempool_txs = NULL;
    size_t num_txs = get_mempool_transactions(&mempool_txs);
    
    // Check if verbose mode is requested
    int verbose = 0;
    if (params) {
        struct json_object* params_obj = json_tokener_parse(params);
        if (params_obj && json_object_is_type(params_obj, json_type_array)) {
            struct json_object* verbose_obj = json_object_array_get_idx(params_obj, 0);
            if (verbose_obj && json_object_is_type(verbose_obj, json_type_boolean)) {
                verbose = json_object_get_boolean(verbose_obj);
            }
        }
        if (params_obj) json_object_put(params_obj);
    }

    if (verbose) {
        // Verbose mode - return detailed info about each tx
        for (size_t i = 0; i < num_txs; i++) {
            transaction_t* tx = mempool_txs[i];
            if (!tx || !tx->id) continue;

            char* txid = bin2hex(tx->id, HASH_SIZE);
            struct json_object* tx_info = json_object_new_object();

            // Calculate sizes
            size_t vsize = get_tx_header_size(tx);
            uint64_t fee = calculate_transaction_fee(tx);
            double fee_per_byte = fee > 0 ? (double)fee / vsize : 0.0;

            json_object_object_add(tx_info, "vsize", json_object_new_int(vsize));
            json_object_object_add(tx_info, "fee", json_object_new_double((double)fee / COIN));
            json_object_object_add(tx_info, "modifiedfee", json_object_new_double((double)fee / COIN));
            json_object_object_add(tx_info, "time", json_object_new_int(get_current_time()));
            json_object_object_add(tx_info, "height", json_object_new_int(get_block_height()));
            json_object_object_add(tx_info, "descendantcount", json_object_new_int(1));
            json_object_object_add(tx_info, "descendantsize", json_object_new_int(vsize));
            json_object_object_add(tx_info, "descendantfees", json_object_new_int(fee));
            json_object_object_add(tx_info, "ancestorcount", json_object_new_int(1));
            json_object_object_add(tx_info, "ancestorsize", json_object_new_int(vsize));
            json_object_object_add(tx_info, "ancestorfees", json_object_new_int(fee));
            json_object_object_add(tx_info, "wtxid", json_object_new_string(txid));
            json_object_object_add(tx_info, "fees", json_object_new_object());
            json_object_object_add(tx_info, "depends", json_object_new_array());
            json_object_object_add(tx_info, "spentby", json_object_new_array());
            json_object_object_add(tx_info, "bip125-replaceable", json_object_new_boolean(false));
            
            struct json_object* fees = json_object_object_get(tx_info, "fees");
            json_object_object_add(fees, "base", json_object_new_double((double)fee / COIN));
            json_object_object_add(fees, "modified", json_object_new_double((double)fee / COIN));
            json_object_object_add(fees, "ancestor", json_object_new_double((double)fee / COIN));
            json_object_object_add(fees, "descendant", json_object_new_double((double)fee / COIN));

            json_object_object_add(result, txid, tx_info);
            free(txid);
        }
    } else {
        // Non-verbose mode - just return array of txids
        result = json_object_new_array();
        for (size_t i = 0; i < num_txs; i++) {
            transaction_t* tx = mempool_txs[i];
            if (tx && tx->id) {
                char* txid = bin2hex(tx->id, HASH_SIZE);
                json_object_array_add(result, json_object_new_string(txid));
                free(txid);
            }
        }
    }
    
    // Free temporary array
    if (mempool_txs) {
        free(mempool_txs);
    }
    
    json_object_object_add(response, "result", result);
    json_object_object_add(response, "error", NULL);
    json_object_object_add(response, "id", json_object_new_int(1));
    
    char* json_str = strdup(json_object_to_json_string(response));
    json_object_put(response);
    return json_str;
}

char* rpc_getmempoolfeeinfo(const char* params) {
    struct json_object* response = json_object_new_object();
    struct json_object* result = json_object_new_object();
    struct json_object* buckets = json_object_new_array();

    // Get transactions from mempool
    transaction_t** mempool_txs = NULL;
    size_t num_txs = get_mempool_transactions(&mempool_txs);

    // Create fee buckets (in sats/byte)
    double fee_buckets[] = {1, 2, 3, 4, 5, 10, 15, 20, 30, 40, 50, 60, 70, 80, 90, 100, 125, 150, 175, 200, 250};
    int num_buckets = sizeof(fee_buckets) / sizeof(fee_buckets[0]);
    int* bucket_counts = calloc(num_buckets, sizeof(int));

    // Count transactions in each fee bucket
    for (size_t i = 0; i < num_txs; i++) {
        transaction_t* tx = mempool_txs[i];
        if (!tx) continue;

        uint64_t fee = calculate_transaction_fee(tx);
        size_t tx_size = get_tx_header_size(tx);
        
        if (tx_size > 0) {
            double fee_rate = (double)fee / tx_size;
            
            // Find appropriate bucket
            for (int j = 0; j < num_buckets; j++) {
                if (fee_rate <= fee_buckets[j]) {
                    bucket_counts[j]++;
                    break;
                }
            }
        }
    }

    // Create bucket objects
    for (int i = 0; i < num_buckets; i++) {
        struct json_object* bucket = json_object_new_object();
        json_object_object_add(bucket, "fee", json_object_new_double(fee_buckets[i]));
        json_object_object_add(bucket, "count", json_object_new_int(bucket_counts[i]));
        json_object_array_add(buckets, bucket);
    }

    // Free resources
    if (mempool_txs) {
        free(mempool_txs);
    }
    free(bucket_counts);

    // Build response
    json_object_object_add(result, "buckets", buckets);
    json_object_object_add(response, "result", result);
    json_object_object_add(response, "error", NULL);
    json_object_object_add(response, "id", json_object_new_int(1));

    char* json_str = strdup(json_object_to_json_string(response));
    json_object_put(response);
    return json_str;
}

char* rpc_getpeerinfo(const char* params) {
    struct json_object* response = json_object_new_object();
    struct json_object* result = json_object_new_array();
    
    // Get connected peers
    peer_t** peers = NULL;
    size_t num_peers = get_connected_peers(&peers);
    
    // Add peer info to response
    for (size_t i = 0; i < num_peers; i++) {
        peer_t* peer = peers[i];
        if (!peer) continue;
        
        struct json_object* peer_obj = json_object_new_object();
        
        // Add basic peer info
        char addr_str[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET, (void*)&peer->net_connection->connection->sa.sin.sin_addr, addr_str, sizeof(addr_str));
        json_object_object_add(peer_obj, "addr", json_object_new_string(addr_str));
        json_object_object_add(peer_obj, "port", json_object_new_int(ntohs((void*)&peer->net_connection->connection->sa.sin.sin_port)));
        
        // Connection info
        json_object_object_add(peer_obj, "conntime", json_object_new_int64(peer->connect_time));
        json_object_object_add(peer_obj, "lastsend", json_object_new_int64(peer->last_send));
        json_object_object_add(peer_obj, "lastrecv", json_object_new_int64(peer->last_recv));
        json_object_object_add(peer_obj, "version", json_object_new_int(peer->version));
        json_object_object_add(peer_obj, "subver", json_object_new_string(peer->user_agent ? peer->user_agent : ""));
        json_object_object_add(peer_obj, "inbound", json_object_new_boolean(peer->inbound));
        json_object_object_add(peer_obj, "startingheight", json_object_new_int(peer->start_height));
        json_object_object_add(peer_obj, "synced_headers", json_object_new_int(peer->sync_height));
        json_object_object_add(peer_obj, "synced_blocks", json_object_new_int(peer->sync_height));
        
        // Network stats
        json_object_object_add(peer_obj, "bytessent", json_object_new_int64(peer->bytes_sent));  
        json_object_object_add(peer_obj, "bytesrecv", json_object_new_int64(peer->bytes_received));
        
        // Add peer state info
        json_object_object_add(peer_obj, "banscore", json_object_new_int(peer->misbehaving));
        json_object_object_add(peer_obj, "relaytxes", json_object_new_boolean(1));
        
        json_object_array_add(result, peer_obj);
    }
    
    // Free temporary array 
    if (peers) {
        free(peers);
    }
    
    json_object_object_add(response, "result", result);
    json_object_object_add(response, "error", NULL);
    json_object_object_add(response, "id", json_object_new_int(1));
    
    char* json_str = strdup(json_object_to_json_string(response));
    json_object_put(response);
    return json_str;
}

char* rpc_getchaintxstats(const char* params) {
    struct json_object* response = json_object_new_object();
    struct json_object* result = json_object_new_object();
    
    // Parameters: 
    // 1. nblocks (numeric, optional, default=one month) - Size of the window in number of blocks
    // 2. blockhash (string, optional) - The hash of the block that ends the window
    int window = 30 * 24 * 60 / POW_TARGET_SPACING; // Default ~1 month of blocks
    uint8_t* block_hash = NULL;
    
    if (params) {
        struct json_object* params_obj = json_tokener_parse(params);
        if (params_obj && json_object_is_type(params_obj, json_type_array)) {
            // Get nblocks parameter
            struct json_object* window_obj = json_object_array_get_idx(params_obj, 0);
            if (window_obj && json_object_is_type(window_obj, json_type_int)) {
                window = json_object_get_int(window_obj);
            }
            
            // Get blockhash parameter
            struct json_object* hash_obj = json_object_array_get_idx(params_obj, 1);
            if (hash_obj && json_object_is_type(hash_obj, json_type_string)) {
                size_t hash_len;
                block_hash = hex2bin(json_object_get_string(hash_obj), &hash_len);
            }
        }
        if (params_obj) json_object_put(params_obj);
    }

    // Handle negative or zero window values - cap at chain height
    if (window <= 0) window = 1;
    uint32_t max_height = get_block_height();
    if ((uint32_t)window > max_height) {
        window = max_height;
    }

    // Get final block - either specified by hash or current tip
    block_t* final_block = NULL;
    if (block_hash) {
        final_block = get_block_from_hash(block_hash);
        free(block_hash);
        if (!final_block) {
            return create_json_error(-8, "Invalid block hash");
        }
    } else {
        final_block = get_top_block();
        if (!final_block) {
            return create_json_error(-8, "Could not get chain tip");
        }
    }

    uint32_t final_height = get_block_height_from_block(final_block);

    // Calculate start height and get start block
    uint32_t start_height = (final_height > window) ? (final_height - window) : 0;
    block_t* start_block = get_block_from_height(start_height);
    
    if (!start_block) {
        free_block(final_block);
        return create_json_error(-8, "Could not get start block");
    }

    uint64_t total_tx_count = 0;
    uint64_t window_tx_count = 0;
    
    // Get total tx count up to final block
    for (uint32_t height = 0; height <= final_height; height++) {
        block_t* block = get_block_from_height(height);
        if (!block) continue;
        total_tx_count += block->transaction_count;
        if (height >= start_height) {
            window_tx_count += block->transaction_count;
        }
        free_block(block);
    }

    // Calculate time difference and averages
    int64_t time_diff = (int64_t)final_block->timestamp - (int64_t)start_block->timestamp;
    if (time_diff <= 0) time_diff = 1; // Avoid division by zero

    double tx_rate = (double)window_tx_count / time_diff;
    double avg_timespan = (double)time_diff / window;

    // Fill in response fields
    json_object_object_add(result, "time", json_object_new_int64(final_block->timestamp));
    json_object_object_add(result, "txcount", json_object_new_int64(total_tx_count));
    json_object_object_add(result, "window_final_block_hash", 
        json_object_new_string(bin2hex(final_block->hash, HASH_SIZE)));
    json_object_object_add(result, "window_block_count", json_object_new_int(window));
    json_object_object_add(result, "window_tx_count", json_object_new_int64(window_tx_count));
    json_object_object_add(result, "window_interval", json_object_new_int64(time_diff));
    json_object_object_add(result, "txrate", json_object_new_double(tx_rate));
    json_object_object_add(result, "avgTimespan", json_object_new_double(avg_timespan));

    // Add response
    json_object_object_add(response, "result", result);
    json_object_object_add(response, "error", NULL);
    json_object_object_add(response, "id", json_object_new_int(1));

    free_block(final_block);
    free_block(start_block);

    char* json_str = strdup(json_object_to_json_string(response));
    json_object_put(response);
    return json_str;
}

char* rpc_sendrawtransaction(const char* params) {
    if (!params) {
        return create_json_error(-32602, "Invalid params");
    }

    struct json_object* params_obj = json_tokener_parse(params);
    if (!params_obj || !json_object_is_type(params_obj, json_type_array)) {
        if (params_obj) json_object_put(params_obj);
        return create_json_error(-32602, "Invalid params - must be JSON array");
    }

    // Get hex transaction parameter
    struct json_object* hex_obj = json_object_array_get_idx(params_obj, 0);
    if (!hex_obj || !json_object_is_type(hex_obj, json_type_string)) {
        json_object_put(params_obj);
        return create_json_error(-32602, "Invalid params - transaction hex required");
    }

    // Decode hex transaction
    const char* tx_hex = json_object_get_string(hex_obj);
    size_t tx_data_len;
    uint8_t* tx_data = hex2bin(tx_hex, &tx_data_len);
    
    if (!tx_data) {
        json_object_put(params_obj);
        return create_json_error(-22, "Invalid transaction hex");
    }

    // Deserialize transaction
    buffer_t* buffer = buffer_init_data(0, tx_data, tx_data_len);
    buffer_iterator_t* iterator = buffer_iterator_init(buffer);
    transaction_t* tx = NULL;

    if (deserialize_transaction(iterator, &tx)) {
        free(tx_data);
        buffer_iterator_free(iterator);
        buffer_free(buffer);
        json_object_put(params_obj);
        return create_json_error(-22, "Transaction decode failed");
    }

    // Validate and add to mempool
    if (validate_and_add_tx_to_mempool(tx)) {
        free(tx_data);
        buffer_iterator_free(iterator);
        buffer_free(buffer);
        free_transaction(tx);
        json_object_put(params_obj);
        return create_json_error(-26, "Transaction validation failed");
    }

    // Return transaction id
    char* txid = bin2hex(tx->id, HASH_SIZE);
    struct json_object* response = json_object_new_object();
    json_object_object_add(response, "result", json_object_new_string(txid));
    json_object_object_add(response, "error", NULL);
    json_object_object_add(response, "id", json_object_new_int(1));

    free(txid);
    free(tx_data);
    buffer_iterator_free(iterator);
    buffer_free(buffer);
    free_transaction(tx);
    json_object_put(params_obj);

    char* json_str = strdup(json_object_to_json_string(response));
    json_object_put(response);
    return json_str;
}

char* rpc_createrawtransaction(const char* params) {
    if (!params) {
        return create_json_error(-32602, "Invalid params");
    }

    struct json_object* params_obj = json_tokener_parse(params);
    if (!params_obj || !json_object_is_type(params_obj, json_type_array)) {
        if (params_obj) json_object_put(params_obj);
        return create_json_error(-32602, "Invalid params - must be JSON array");
    }

    // Get inputs array
    struct json_object* inputs = json_object_array_get_idx(params_obj, 0);
    if (!inputs || !json_object_is_type(inputs, json_type_array)) {
        json_object_put(params_obj);
        return create_json_error(-32602, "Invalid inputs parameter");
    }

    // Get outputs object
    struct json_object* outputs = json_object_array_get_idx(params_obj, 1);
    if (!outputs || !json_object_is_type(outputs, json_type_object)) {
        json_object_put(params_obj);
        return create_json_error(-32602, "Invalid outputs parameter");
    }

    // Create new transaction
    transaction_t* tx = create_new_transaction();

    // Add inputs
    int array_len = json_object_array_length(inputs);
    for (int i = 0; i < array_len; i++) {
        struct json_object* input = json_object_array_get_idx(inputs, i);
        
        struct json_object* txid_obj;
        struct json_object* vout_obj;
        if (!json_object_object_get_ex(input, "txid", &txid_obj) ||
            !json_object_object_get_ex(input, "vout", &vout_obj)) {
            free_transaction(tx);
            json_object_put(params_obj);
            return create_json_error(-32602, "Invalid input parameters");
        }

        // Create input transaction
        input_transaction_t* txin = create_new_txin();
        const char* txid = json_object_get_string(txid_obj);
        size_t txid_len;
        uint8_t* txid_bin = hex2bin(txid, &txid_len);
        memcpy(txin->transaction, txid_bin, HASH_SIZE);
        free(txid_bin);
        
        txin->txout_index = json_object_get_int(vout_obj);
        
        // Add to transaction
        if (add_txin_to_transaction(tx, txin, tx->txin_count)) {
            free_transaction(tx);
            json_object_put(params_obj);
            return create_json_error(-22, "Failed to add input");
        }
    }

    // Add outputs
    struct json_object_iter it;
    json_object_object_foreachC(outputs, it) {
        const char* address = it.key;
        double amount = json_object_get_double(it.val);
        
        // Create output transaction
        output_transaction_t* txout = create_new_txout();
        txout->amount = amount * COIN;
        
        size_t addr_len;
        uint8_t* addr_bin = hex2bin(address, &addr_len);
        if (addr_len != ADDRESS_SIZE) {
            free(addr_bin);
            free_transaction(tx);
            json_object_put(params_obj);
            return create_json_error(-5, "Invalid address");
        }
        memcpy(txout->address, addr_bin, ADDRESS_SIZE);
        free(addr_bin);

        // Add to transaction
        if (add_txout_to_transaction(tx, txout, tx->txout_count)) {
            free_transaction(tx);
            json_object_put(params_obj);
            return create_json_error(-22, "Failed to add output");
        }
    }

    // Compute transaction ID
    compute_self_tx_id(tx);

    // Serialize transaction
    buffer_t* buffer = buffer_init();
    serialize_transaction(buffer, tx);
    char* tx_hex = bin2hex(buffer_get_data(buffer), buffer_get_size(buffer));

    struct json_object* response = json_object_new_object();
    json_object_object_add(response, "result", json_object_new_string(tx_hex));
    json_object_object_add(response, "error", NULL);
    json_object_object_add(response, "id", json_object_new_int(1));

    free(tx_hex);
    buffer_free(buffer);
    free_transaction(tx);
    json_object_put(params_obj);

    char* json_str = strdup(json_object_to_json_string(response));
    json_object_put(response);
    return json_str;
}

char* rpc_decoderawtransaction(const char* params) {
    if (!params) {
        return create_json_error(-32602, "Invalid params");
    }

    struct json_object* params_obj = json_tokener_parse(params);
    if (!params_obj || !json_object_is_type(params_obj, json_type_array)) {
        if (params_obj) json_object_put(params_obj);
        return create_json_error(-32602, "Invalid params - must be JSON array");
    }

    // Get hex string parameter
    struct json_object* hex_obj = json_object_array_get_idx(params_obj, 0);
    if (!hex_obj || !json_object_is_type(hex_obj, json_type_string)) {
        json_object_put(params_obj);
        return create_json_error(-32602, "Invalid transaction hex");
    }

    const char* tx_hex = json_object_get_string(hex_obj);
    size_t tx_data_len;
    uint8_t* tx_data = hex2bin(tx_hex, &tx_data_len);

    // Deserialize transaction
    buffer_t* buffer = buffer_init_data(0, tx_data, tx_data_len);
    buffer_iterator_t* iterator = buffer_iterator_init(buffer);
    transaction_t* tx = NULL;

    if (deserialize_transaction(iterator, &tx)) {
        free(tx_data);
        buffer_iterator_free(iterator);
        buffer_free(buffer);
        json_object_put(params_obj);
        return create_json_error(-22, "Transaction decode failed");
    }

    struct json_object* response = json_object_new_object();
    struct json_object* result = json_object_new_object();

    // Add transaction details
    char* txid = bin2hex(tx->id, HASH_SIZE);
    json_object_object_add(result, "txid", json_object_new_string(txid));
    json_object_object_add(result, "size", json_object_new_int(get_tx_header_size(tx)));
    json_object_object_add(result, "version", json_object_new_int(tx->version));
    
    // Add vin array
    struct json_object* vin = json_object_new_array();
    for (uint32_t i = 0; i < tx->txin_count; i++) {
        input_transaction_t* txin = tx->txins[i];
        struct json_object* input = json_object_new_object();
        
        if (is_coinbase_tx(tx)) {
            json_object_object_add(input, "coinbase", json_object_new_string(""));
        } else {
            char* prev_txid = bin2hex(txin->transaction, HASH_SIZE);
            json_object_object_add(input, "txid", json_object_new_string(prev_txid));
            json_object_object_add(input, "vout", json_object_new_int(txin->txout_index));
            free(prev_txid);
        }
        
        json_object_array_add(vin, input);
    }
    json_object_object_add(result, "vin", vin);

    // Add vout array
    struct json_object* vout = json_object_new_array();
    for (uint32_t i = 0; i < tx->txout_count; i++) {
        output_transaction_t* txout = tx->txouts[i];
        struct json_object* output = json_object_new_object();
        
        char value_str[32];
        snprintf(value_str, sizeof(value_str), "%.8f", (double)txout->amount / COIN);
        json_object_object_add(output, "value", json_object_new_string(value_str));
        json_object_object_add(output, "n", json_object_new_int(i));
        
        struct json_object* script_pub_key = json_object_new_object();
        char* addr = bin2hex(txout->address, ADDRESS_SIZE);
        json_object_object_add(script_pub_key, "addresses", json_object_new_array());
        json_object_object_add(script_pub_key, "type", json_object_new_string("pubkeyhash"));
        json_object_object_add(output, "scriptPubKey", script_pub_key);
        free(addr);
        
        json_object_array_add(vout, output);
    }
    json_object_object_add(result, "vout", vout);

    json_object_object_add(response, "result", result);
    json_object_object_add(response, "error", NULL);
    json_object_object_add(response, "id", json_object_new_int(1));

    free(txid);
    free(tx_data);
    buffer_iterator_free(iterator);
    buffer_free(buffer);
    free_transaction(tx);
    json_object_put(params_obj);

    char* json_str = strdup(json_object_to_json_string(response));
    json_object_put(response);
    return json_str;
}

char* rpc_testmempoolaccept(const char* params) {
    if (!params) {
        return create_json_error(-32602, "Invalid params");
    }

    struct json_object* params_obj = json_tokener_parse(params);
    if (!params_obj || !json_object_is_type(params_obj, json_type_array)) {
        if (params_obj) json_object_put(params_obj);
        return create_json_error(-32602, "Invalid params - must be JSON array");
    }

    // Get rawtxs array
    struct json_object* rawtxs = json_object_array_get_idx(params_obj, 0);
    if (!rawtxs || !json_object_is_type(rawtxs, json_type_array)) {
        json_object_put(params_obj);
        return create_json_error(-32602, "Invalid rawtxs parameter");
    }

    struct json_object* response = json_object_new_object();
    struct json_object* result = json_object_new_array();

    // Process each transaction
    int num_txs = json_object_array_length(rawtxs);
    for (int i = 0; i < num_txs; i++) {
        struct json_object* rawtx_obj = json_object_array_get_idx(rawtxs, i);
        const char* rawtx = json_object_get_string(rawtx_obj);

        // Decode and validate transaction
        size_t tx_data_len;
        uint8_t* tx_data = hex2bin(rawtx, &tx_data_len);
        
        buffer_t* buffer = buffer_init_data(0, tx_data, tx_data_len);
        buffer_iterator_t* iterator = buffer_iterator_init(buffer);
        transaction_t* tx = NULL;

        struct json_object* tx_result = json_object_new_object();

        if (deserialize_transaction(iterator, &tx)) {
            json_object_object_add(tx_result, "txid", json_object_new_string(""));
            json_object_object_add(tx_result, "allowed", json_object_new_boolean(false));
            json_object_object_add(tx_result, "reject-reason", json_object_new_string("Transaction decode failed"));
        } else {
            char* txid = bin2hex(tx->id, HASH_SIZE);
            json_object_object_add(tx_result, "txid", json_object_new_string(txid));
            
            // Test if transaction would be accepted to mempool
            if (valid_transaction(tx)) {
                json_object_object_add(tx_result, "allowed", json_object_new_boolean(true));
            } else {
                json_object_object_add(tx_result, "allowed", json_object_new_boolean(false));
                json_object_object_add(tx_result, "reject-reason", json_object_new_string("Transaction validation failed"));
            }
            
            free(txid);
            free_transaction(tx);
        }

        free(tx_data);
        buffer_iterator_free(iterator);
        buffer_free(buffer);

        json_object_array_add(result, tx_result);
    }

    json_object_object_add(response, "result", result);
    json_object_object_add(response, "error", NULL);
    json_object_object_add(response, "id", json_object_new_int(1));

    json_object_put(params_obj);

    char* json_str = strdup(json_object_to_json_string(response));
    json_object_put(response);
    return json_str;
}

char* rpc_gettxout(const char* params) {
    if (!params) {
        return create_json_error(-32602, "Invalid params");
    }

    struct json_object* params_obj = json_tokener_parse(params);
    if (!params_obj || !json_object_is_type(params_obj, json_type_array)) {
        if (params_obj) json_object_put(params_obj);
        return create_json_error(-32602, "Invalid params - must be JSON array");
    }

    // Get txid and n parameters
    struct json_object* txid_obj = json_object_array_get_idx(params_obj, 0);
    struct json_object* vout_obj = json_object_array_get_idx(params_obj, 1);
    if (!txid_obj || !json_object_is_type(txid_obj, json_type_string) ||
        !vout_obj || !json_object_is_type(vout_obj, json_type_int)) {
        json_object_put(params_obj);
        return create_json_error(-32602, "Invalid parameters");
    }

    const char* txid = json_object_get_string(txid_obj);
    int vout = json_object_get_int(vout_obj);
    
    // Convert txid to binary
    size_t txid_len;
    uint8_t* txid_bin = hex2bin(txid, &txid_len);
    if (!txid_bin || txid_len != HASH_SIZE) {
        if (txid_bin) free(txid_bin);
        json_object_put(params_obj);
        return create_json_error(-32602, "Invalid txid");
    }

    // Look up the transaction
    block_t* block = get_block_from_tx_id(txid_bin);
    free(txid_bin);

    if (!block) {
        json_object_put(params_obj);
        return create_json_error(-5, "Transaction not found");
    }

    // Find transaction and validate vout
    transaction_t* tx = NULL;
    for (uint32_t i = 0; i < block->transaction_count; i++) {
        if (memcmp(block->transactions[i]->id, txid_bin, HASH_SIZE) == 0) {
            tx = block->transactions[i];
            break;
        }
    }

    if (!tx || vout < 0 || (uint32_t)vout >= tx->txout_count) {
        free_block(block);
        json_object_put(params_obj);
        return create_json_error(-5, "Output not found");
    }

    output_transaction_t* txout = tx->txouts[vout];
    
    struct json_object* response = json_object_new_object();
    struct json_object* result = json_object_new_object();

    json_object_object_add(result, "bestblock", json_object_new_string(bin2hex(block->hash, HASH_SIZE)));
    json_object_object_add(result, "confirmations", json_object_new_int(get_blocks_since_block(block)));
    json_object_object_add(result, "value", json_object_new_double((double)txout->amount / COIN));
    
    struct json_object* scriptPubKey = json_object_new_object();
    char* addr = bin2hex(txout->address, ADDRESS_SIZE);
    json_object_object_add(scriptPubKey, "address", json_object_new_string(addr));
    json_object_object_add(scriptPubKey, "type", json_object_new_string("pubkeyhash"));
    json_object_object_add(result, "scriptPubKey", scriptPubKey);
    free(addr);

    json_object_object_add(response, "result", result);
    json_object_object_add(response, "error", NULL);
    json_object_object_add(response, "id", json_object_new_int(1));

    free_block(block);
    json_object_put(params_obj);

    char* json_str = strdup(json_object_to_json_string(response));
    json_object_put(response);
    return json_str;
}

char* rpc_pruneblockchain(const char* params) {
    // Not implementing actual pruning, just return current height
    struct json_object* response = json_object_new_object();
    json_object_object_add(response, "result", json_object_new_int(get_block_height()));
    json_object_object_add(response, "error", NULL);
    json_object_object_add(response, "id", json_object_new_int(1));

    char* json_str = strdup(json_object_to_json_string(response));
    json_object_put(response);
    return json_str;
}

char* rpc_gettxoutproof(const char* params) {
    // Simplified implementation - returns error as this is optional
    return create_json_error(-1, "Not implemented");
}

char* rpc_verifytxoutproof(const char* params) {
    // Simplified implementation - returns error as this is optional  
    return create_json_error(-1, "Not implemented");
}

char* rpc_verifychain(const char* params) {
    // For now just returns true if we have blocks
    struct json_object* response = json_object_new_object();
    json_object_object_add(response, "result", json_object_new_boolean(get_block_height() > 0));
    json_object_object_add(response, "error", NULL);
    json_object_object_add(response, "id", json_object_new_int(1));

    char* json_str = strdup(json_object_to_json_string(response));
    json_object_put(response);
    return json_str;
}

char* rpc_invalidateblock(const char* params) {
    // Not implementing actual block invalidation
    return create_json_error(-1, "Not implemented");
}

char* rpc_reconsiderblock(const char* params) {
    // Not implementing actual block reconsideration
    return create_json_error(-1, "Not implemented"); 
}

char* rpc_waitfornewblock(const char* params) {
    // Not implementing actual waiting - return current tip
    struct json_object* response = json_object_new_object();
    struct json_object* result = json_object_new_object();
    
    block_t* tip = get_top_block();
    if (tip) {
        json_object_object_add(result, "hash", json_object_new_string(bin2hex(tip->hash, HASH_SIZE)));
        json_object_object_add(result, "height", json_object_new_int(get_block_height()));
        free_block(tip);
    }
    
    json_object_object_add(response, "result", result);
    json_object_object_add(response, "error", NULL);
    json_object_object_add(response, "id", json_object_new_int(1));

    char* json_str = strdup(json_object_to_json_string(response));
    json_object_put(response);
    return json_str;
}

char* rpc_waitforblock(const char* params) {
    // Similar to waitfornewblock but accepts blockhash parameter
    if (!params) return rpc_waitfornewblock(NULL);
    return rpc_waitfornewblock(NULL); // For now just reuse waitfornewblock
}

char* rpc_setnetworkactive(const char* params) {
    // Not implementing actual network toggling
    struct json_object* response = json_object_new_object();
    json_object_object_add(response, "result", json_object_new_boolean(1));
    json_object_object_add(response, "error", NULL);
    json_object_object_add(response, "id", json_object_new_int(1));

    char* json_str = strdup(json_object_to_json_string(response));
    json_object_put(response);
    return json_str;
}

char* rpc_addnode(const char* params) {
    if (!params) {
        return create_json_error(-32602, "Invalid params");
    }

    struct json_object* params_obj = json_tokener_parse(params);
    if (!params_obj || !json_object_is_type(params_obj, json_type_array)) {
        if (params_obj) json_object_put(params_obj);
        return create_json_error(-32602, "Invalid params - must be JSON array");
    }

    struct json_object* node_obj = json_object_array_get_idx(params_obj, 0);
    struct json_object* command_obj = json_object_array_get_idx(params_obj, 1);

    if (!node_obj || !command_obj) {
        json_object_put(params_obj);
        return create_json_error(-32602, "Invalid parameters");
    }

    const char* node = json_object_get_string(node_obj);
    const char* command = json_object_get_string(command_obj);

    // Connect to node if command is "add" or "onetry"
    if (strcmp(command, "add") == 0 || strcmp(command, "onetry") == 0) {
        // Parse IP and port
        char ip[64];
        uint16_t port = 8333;
        sscanf(node, "%[^:]:%hu", ip, &port);
        
        int result = connect_net_to_peer(ip, port);
        if (result) {
            json_object_put(params_obj);
            return create_json_error(-9, "Failed to connect to node");
        }
    }

    struct json_object* response = json_object_new_object();
    json_object_object_add(response, "result", NULL);
    json_object_object_add(response, "error", NULL);
    json_object_object_add(response, "id", json_object_new_int(1));

    json_object_put(params_obj);

    char* json_str = strdup(json_object_to_json_string(response));
    json_object_put(response);
    return json_str;
}

char* rpc_disconnectnode(const char* params) {
    if (!params) {
        return create_json_error(-32602, "Invalid params");
    }

    struct json_object* params_obj = json_tokener_parse(params);
    if (!params_obj || !json_object_is_type(params_obj, json_type_array)) {
        if (params_obj) json_object_put(params_obj);
        return create_json_error(-32602, "Invalid params - must be JSON array");
    }

    struct json_object* address_obj = json_object_array_get_idx(params_obj, 0);
    if (!address_obj) {
        json_object_put(params_obj);
        return create_json_error(-32602, "Invalid parameters");
    }

    const char* address = json_object_get_string(address_obj);
    
    // Parse IP and port
    char ip[64];
    uint16_t port = 8333;
    sscanf(address, "%[^:]:%hu", ip, &port);

    // Disconnect peer
    //disconnect_peer_by_address(ip, port); // TODO: IMPLEMENT ME!

    struct json_object* response = json_object_new_object();
    json_object_object_add(response, "result", NULL);
    json_object_object_add(response, "error", NULL);
    json_object_object_add(response, "id", json_object_new_int(1));

    json_object_put(params_obj);

    char* json_str = strdup(json_object_to_json_string(response));
    json_object_put(response);
    return json_str;
}

char* rpc_getaddednodeinfo(const char* params) {
    struct json_object* response = json_object_new_object();
    struct json_object* result = json_object_new_array();

    // Get connected peers
    peer_t** peers = NULL;
    size_t num_peers = get_connected_peers(&peers);
    
    for (size_t i = 0; i < num_peers; i++) {
        peer_t* peer = peers[i];
        if (!peer) continue;

        struct json_object* node = json_object_new_object();
        
        char addr_str[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET, (void*)&peer->net_connection->connection->sa.sin.sin_addr, addr_str, sizeof(addr_str));
        
        json_object_object_add(node, "addednode", json_object_new_string(addr_str));
        json_object_object_add(node, "connected", json_object_new_boolean(1));
        
        json_object_array_add(result, node);
    }

    if (peers) free(peers);

    json_object_object_add(response, "result", result);
    json_object_object_add(response, "error", NULL);
    json_object_object_add(response, "id", json_object_new_int(1));

    char* json_str = strdup(json_object_to_json_string(response));
    json_object_put(response);
    return json_str;
}

char* rpc_setban(const char* params) {
    // Not implementing actual banning
    struct json_object* response = json_object_new_object();
    json_object_object_add(response, "result", NULL);
    json_object_object_add(response, "error", NULL);
    json_object_object_add(response, "id", json_object_new_int(1));

    char* json_str = strdup(json_object_to_json_string(response));
    json_object_put(response);
    return json_str;
}

char* rpc_listbanned(const char* params) {
    // Return empty array since we don't implement banning
    struct json_object* response = json_object_new_object();
    json_object_object_add(response, "result", json_object_new_array());
    json_object_object_add(response, "error", NULL);
    json_object_object_add(response, "id", json_object_new_int(1));

    char* json_str = strdup(json_object_to_json_string(response));
    json_object_put(response);
    return json_str;
}

char* rpc_clearbanned(const char* params) {
    // No-op since we don't implement banning
    struct json_object* response = json_object_new_object();
    json_object_object_add(response, "result", NULL);
    json_object_object_add(response, "error", NULL);
    json_object_object_add(response, "id", json_object_new_int(1));

    char* json_str = strdup(json_object_to_json_string(response));
    json_object_put(response);
    return json_str;
}

char* rpc_ping(const char* params) {
    // Broadcast ping message to peers
    //broadcast_ping(); // TODO: IMPLEMENT ME!

    struct json_object* response = json_object_new_object();
    json_object_object_add(response, "result", NULL);
    json_object_object_add(response, "error", NULL);
    json_object_object_add(response, "id", json_object_new_int(1));

    char* json_str = strdup(json_object_to_json_string(response));
    json_object_put(response);
    return json_str;
}