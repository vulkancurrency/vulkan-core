#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>

#include <json-c/json.h>

#include "common/logger.h"

#include "crypto/cryptoutil.h"

#include "rpc_server.h"
#include "blockchain.h"
#include "block.h"
#include "mempool.h"
#include "pow.h"

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

static void handle_client(int client_fd, rpc_server_t* server) {
    char buffer[RPC_BUFFER_SIZE];
    ssize_t bytes_read = read(client_fd, buffer, sizeof(buffer) - 1);
    
    if (bytes_read > 0) {
        buffer[bytes_read] = '\0';
        
        struct json_object* request = json_tokener_parse(buffer);
        if (!request) {
            char* error = create_json_error(-32700, "Parse error");
            write(client_fd, error, strlen(error));
            free(error);
            close(client_fd);
            return;
        }
        
        struct json_object* method_obj;
        json_object_object_get_ex(request, "method", &method_obj);
        const char* method_name = json_object_get_string(method_obj);
        
        struct json_object* params_obj;
        json_object_object_get_ex(request, "params", &params_obj);
        const char* params = json_object_get_string(params_obj);
        
        // Find and execute the RPC method
        rpc_method_t* method = rpc_methods;
        while (method->name) {
            if (strcmp(method->name, method_name) == 0) {
                char* result = method->handler(params);
                write(client_fd, result, strlen(result));
                free(result);
                close(client_fd);
                return;
            }
            method++;
        }
        
        // Method not found
        char* error = create_json_error(-32601, "Method not found");
        write(client_fd, error, strlen(error));
        free(error);
    }
    
    close(client_fd);
}

int rpc_server_init(rpc_server_t* server, uint16_t port, const char* username, const char* password) {
    server->port = port;
    server->username = strdup(username);
    server->password = strdup(password);
    server->running = 0;
    
    server->socket_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server->socket_fd < 0) {
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
    
    while (server->running) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        
        int client_fd = accept(server->socket_fd, (struct sockaddr*)&client_addr, &client_len);
        if (client_fd < 0) continue;
        
        // Handle client in a new thread
        pthread_t thread;
        pthread_create(&thread, NULL, (void*)handle_client, (void*)client_fd);
        pthread_detach(thread);
    }
    
    return 0;
}

void rpc_server_stop(rpc_server_t* server) {
    server->running = 0;
    close(server->socket_fd);
    free(server->username);
    free(server->password);
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
    struct json_object* request = json_tokener_parse(params);
    int height = json_object_get_int(request);
    
    uint8_t* block_hash = get_block_hash_from_height(height);
    if (!block_hash) {
        return create_json_error(-5, "Block height out of range");
    }
    
    char* hash_hex = bin2hex(block_hash, HASH_SIZE);
    free(block_hash);
    
    struct json_object* response = json_object_new_object();
    json_object_object_add(response, "result", json_object_new_string(hash_hex));
    json_object_object_add(response, "error", NULL);
    json_object_object_add(response, "id", json_object_new_int(1));
    
    free(hash_hex);
    return strdup(json_object_to_json_string(response));
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
