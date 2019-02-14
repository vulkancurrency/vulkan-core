// Copyright (c) 2019, The Vulkan Developers.
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

#include "common/util.h"

#ifdef __cplusplus
extern "C"
{
#endif

typedef struct MerkleNode merkle_node_t;
typedef struct MerkleNode
{
  merkle_node_t *left;
  merkle_node_t *right;
  uint8_t hash[HASH_SIZE];
} merkle_node_t;

typedef struct MerkleTree
{
  merkle_node_t *root;
} merkle_tree_t;

merkle_tree_t *construct_merkle_tree_from_leaves(uint8_t *hashes, uint32_t num_of_hashes);
merkle_node_t *construct_merkle_node(merkle_node_t *left, merkle_node_t *right);

int construct_merkle_leaves_from_hashes(merkle_node_t **nodes, uint32_t *num_of_nodes, uint8_t *hashes, uint32_t num_of_hashes);
int collapse_merkle_nodes(merkle_node_t **nodes, uint32_t *num_of_nodes);

int free_merkle_tree(merkle_tree_t *tree);
int free_merkle_node(merkle_node_t *node);

#ifdef __cplusplus
}
#endif
