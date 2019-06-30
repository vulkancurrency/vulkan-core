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

#include <stdlib.h>
#include <stdint.h>

#include "parameters.h"

static int g_parameters_use_testnet = 0;

void parameters_set_use_testnet(int use_testnet)
{
  g_parameters_use_testnet = use_testnet;
}

const int parameters_get_use_testnet(void)
{
  return g_parameters_use_testnet;
}

const uint8_t parameters_get_address_id(void)
{
  return g_parameters_use_testnet ? TESTNET_ADDRESS_ID : MAINNET_ADDRESS_ID;
}

const uint32_t parameters_get_genesis_nonce(void)
{
  return g_parameters_use_testnet ? TESTNET_GENESIS_NONCE : GENESIS_NONCE;
}

const uint32_t parameters_get_genesis_bits(void)
{
  return g_parameters_use_testnet ? TESTNET_GENESIS_BITS : GENESIS_BITS;
}

const uint32_t parameters_get_genesis_timestamp(void)
{
  return g_parameters_use_testnet ? TESTNET_GENESIS_TIMESTAMP : GENESIS_TIMESTAMP;
}

const uint64_t parameters_get_genesis_reward(void)
{
  return g_parameters_use_testnet ? TESTNET_GENESIS_REWARD : GENESIS_REWARD;
}

const uint64_t parameters_get_pow_target_timespan(void)
{
  return POW_TARGET_TIMESPAN;
}

const uint64_t parameters_get_pow_target_spacing(void)
{
  return POW_TARGET_SPACING;
}

const uint64_t parameters_get_difficulty_adjustment_interval(void)
{
  return parameters_get_pow_target_timespan() / parameters_get_pow_target_spacing();
}

const uint32_t parameters_get_pow_initial_difficulty_bits(void)
{
  return POW_INITIAL_DIFFICULTY_BITS;
}

const int parameters_get_pow_allow_min_difficulty_blocks(void)
{
  return g_parameters_use_testnet ? 1 : 0;
}

const uint16_t parameters_get_p2p_port(void)
{
  return g_parameters_use_testnet ? TESTNET_P2P_PORT : P2P_PORT;
}

const uint16_t parameters_get_rpc_port(void)
{
  return g_parameters_use_testnet ? TESTNET_RPC_PORT : RPC_PORT;
}

const int parameters_get_allow_min_difficulty_blocks(void)
{
  return g_parameters_use_testnet ? 1 : 0;
}
