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

#include <sodium.h>
#include <stdio.h>
#include <protobuf-c-rpc/protobuf-c-rpc.h>

#include "chainparams.h"
#include "wallet.h"
#include "client.h"
#include "vulkan.pb-c.h"

static void handle_get_wallet(const PWallet *wallet, void *closure_data)
{
  int public_address_len = (ADDRESS_SIZE * 2) + 1;
  char public_address[public_address_len];

  for (int i = 0; i < ADDRESS_SIZE; i++)
  {
    sprintf(&public_address[i*2], "%02x", (int) wallet->address.data[i]);
  }

  long double real_balance = ((long double) wallet->balance) / COIN;

  printf("Public Address: %s\n", public_address);
  printf("Balance: %Lf\n", real_balance);

  *(protobuf_c_boolean *) closure_data = 1;
}

int rpc_get_wallet(void)
{
  /*ProtobufCService *service;
  ProtobufC_RPC_Client *client;
  ProtobufC_RPC_AddressType address_type = 0;

  service = protobuf_c_rpc_client_new(address_type, "9898", &pinternal__descriptor, NULL);

  if (service == NULL)
  {
    fprintf(stderr, "Could not create protobuf service\n");
  }

  client = (ProtobufC_RPC_Client *) service;
  printf("Connecting to daemon..\n");

  while(!protobuf_c_rpc_client_is_connected(client))
  {
    protobuf_c_rpc_dispatch_run(protobuf_c_rpc_dispatch_default());
  }

  printf("Connected!\n");

  protobuf_c_boolean is_done = 0;
  PEmpty empty = PEMPTY__INIT;
  pinternal__get_wallet(service, &empty, handle_get_wallet, &is_done);

  while (!is_done)
  {
    protobuf_c_rpc_dispatch_run(protobuf_c_rpc_dispatch_default());
  }*/

  return 0;
}
