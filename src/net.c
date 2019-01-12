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
#include <stdio.h>
#include <string.h>
#include <sodium.h>
#include <protobuf-c-rpc/protobuf-c-rpc.h>

#include "vulkan.pb-c.h"
#include "wallet.h"
#include "transaction.h"
#include "chain.h"

static int g_net_server_running = 0;

static void internal_rpc__get_wallet(PInternal_Service *server,
                                     const PEmpty *input,
                                     PWallet_Closure closure,
                                     void *closure_data)
{
  PWallet *wallet = get_wallet();
  free(wallet->secret_key.data);
  wallet->secret_key.len = 0;
  wallet->secret_key.data = NULL;
  wallet->balance = get_balance_for_address(wallet->address.data);
  closure(wallet, closure_data);
}

static void internal_rpc__send_transaction(PInternal_Service *service,
                                           const PSendTransactionRequest *input,
                                           PSendTransactionResponse_Closure closure,
                                           void *closure_data)
{
  if (input == NULL || input->transaction == NULL)
  {
    closure(NULL, closure_data);
  }
  else
  {
    PTransaction *proto_tx = input->transaction;
    transaction_t *tx = transaction_from_proto(proto_tx);
    PSendTransactionResponse response = PSEND_TRANSACTION_RESPONSE__INIT;

    if (valid_transaction(tx))
    {
      response.transaction_id.len = 32;
      response.transaction_id.data = malloc(sizeof(uint8_t) * 32);
      compute_tx_id(response.transaction_id.data, tx);
    }
    else
    {
      response.transaction_id.len = 0;
    }

    closure(&response, closure_data);
  }
}

static PInternal_Service internal_service = PINTERNAL__INIT(internal_rpc__);

int start_server()
{
  if (g_net_server_running)
  {
    return;
  }
  g_net_server_running = 1;

  ProtobufC_RPC_Server *server;
  ProtobufC_RPC_AddressType address_type = 0;

  server = protobuf_c_rpc_server_new(address_type, "9898", (ProtobufCService *) &internal_service, NULL);
  printf("Internal RPC Server started on port: 9898\n");

  while (g_net_server_running)
  {
    protobuf_c_rpc_dispatch_run(protobuf_c_rpc_dispatch_default());
  }

  return 0;
}

void stop_server()
{
  if (!g_net_server_running)
  {
    return;
  }
  g_net_server_running = 0;
}
