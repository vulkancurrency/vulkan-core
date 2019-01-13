/* Generated by the protocol buffer compiler.  DO NOT EDIT! */
/* Generated from: vulkan.proto */

/* Do not generate deprecated warnings for self */
#ifndef PROTOBUF_C__NO_DEPRECATED
#define PROTOBUF_C__NO_DEPRECATED
#endif

#include "vulkan.pb-c.h"
void   pinput_transaction__init
                     (PInputTransaction         *message)
{
  static const PInputTransaction init_value = PINPUT_TRANSACTION__INIT;
  *message = init_value;
}
size_t pinput_transaction__get_packed_size
                     (const PInputTransaction *message)
{
  assert(message->base.descriptor == &pinput_transaction__descriptor);
  return protobuf_c_message_get_packed_size ((const ProtobufCMessage*)(message));
}
size_t pinput_transaction__pack
                     (const PInputTransaction *message,
                      uint8_t       *out)
{
  assert(message->base.descriptor == &pinput_transaction__descriptor);
  return protobuf_c_message_pack ((const ProtobufCMessage*)message, out);
}
size_t pinput_transaction__pack_to_buffer
                     (const PInputTransaction *message,
                      ProtobufCBuffer *buffer)
{
  assert(message->base.descriptor == &pinput_transaction__descriptor);
  return protobuf_c_message_pack_to_buffer ((const ProtobufCMessage*)message, buffer);
}
PInputTransaction *
       pinput_transaction__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data)
{
  return (PInputTransaction *)
     protobuf_c_message_unpack (&pinput_transaction__descriptor,
                                allocator, len, data);
}
void   pinput_transaction__free_unpacked
                     (PInputTransaction *message,
                      ProtobufCAllocator *allocator)
{
  if(!message)
    return;
  assert(message->base.descriptor == &pinput_transaction__descriptor);
  protobuf_c_message_free_unpacked ((ProtobufCMessage*)message, allocator);
}
void   poutput_transaction__init
                     (POutputTransaction         *message)
{
  static const POutputTransaction init_value = POUTPUT_TRANSACTION__INIT;
  *message = init_value;
}
size_t poutput_transaction__get_packed_size
                     (const POutputTransaction *message)
{
  assert(message->base.descriptor == &poutput_transaction__descriptor);
  return protobuf_c_message_get_packed_size ((const ProtobufCMessage*)(message));
}
size_t poutput_transaction__pack
                     (const POutputTransaction *message,
                      uint8_t       *out)
{
  assert(message->base.descriptor == &poutput_transaction__descriptor);
  return protobuf_c_message_pack ((const ProtobufCMessage*)message, out);
}
size_t poutput_transaction__pack_to_buffer
                     (const POutputTransaction *message,
                      ProtobufCBuffer *buffer)
{
  assert(message->base.descriptor == &poutput_transaction__descriptor);
  return protobuf_c_message_pack_to_buffer ((const ProtobufCMessage*)message, buffer);
}
POutputTransaction *
       poutput_transaction__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data)
{
  return (POutputTransaction *)
     protobuf_c_message_unpack (&poutput_transaction__descriptor,
                                allocator, len, data);
}
void   poutput_transaction__free_unpacked
                     (POutputTransaction *message,
                      ProtobufCAllocator *allocator)
{
  if(!message)
    return;
  assert(message->base.descriptor == &poutput_transaction__descriptor);
  protobuf_c_message_free_unpacked ((ProtobufCMessage*)message, allocator);
}
void   ptransaction__init
                     (PTransaction         *message)
{
  static const PTransaction init_value = PTRANSACTION__INIT;
  *message = init_value;
}
size_t ptransaction__get_packed_size
                     (const PTransaction *message)
{
  assert(message->base.descriptor == &ptransaction__descriptor);
  return protobuf_c_message_get_packed_size ((const ProtobufCMessage*)(message));
}
size_t ptransaction__pack
                     (const PTransaction *message,
                      uint8_t       *out)
{
  assert(message->base.descriptor == &ptransaction__descriptor);
  return protobuf_c_message_pack ((const ProtobufCMessage*)message, out);
}
size_t ptransaction__pack_to_buffer
                     (const PTransaction *message,
                      ProtobufCBuffer *buffer)
{
  assert(message->base.descriptor == &ptransaction__descriptor);
  return protobuf_c_message_pack_to_buffer ((const ProtobufCMessage*)message, buffer);
}
PTransaction *
       ptransaction__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data)
{
  return (PTransaction *)
     protobuf_c_message_unpack (&ptransaction__descriptor,
                                allocator, len, data);
}
void   ptransaction__free_unpacked
                     (PTransaction *message,
                      ProtobufCAllocator *allocator)
{
  if(!message)
    return;
  assert(message->base.descriptor == &ptransaction__descriptor);
  protobuf_c_message_free_unpacked ((ProtobufCMessage*)message, allocator);
}
void   punspent_output_transaction__init
                     (PUnspentOutputTransaction         *message)
{
  static const PUnspentOutputTransaction init_value = PUNSPENT_OUTPUT_TRANSACTION__INIT;
  *message = init_value;
}
size_t punspent_output_transaction__get_packed_size
                     (const PUnspentOutputTransaction *message)
{
  assert(message->base.descriptor == &punspent_output_transaction__descriptor);
  return protobuf_c_message_get_packed_size ((const ProtobufCMessage*)(message));
}
size_t punspent_output_transaction__pack
                     (const PUnspentOutputTransaction *message,
                      uint8_t       *out)
{
  assert(message->base.descriptor == &punspent_output_transaction__descriptor);
  return protobuf_c_message_pack ((const ProtobufCMessage*)message, out);
}
size_t punspent_output_transaction__pack_to_buffer
                     (const PUnspentOutputTransaction *message,
                      ProtobufCBuffer *buffer)
{
  assert(message->base.descriptor == &punspent_output_transaction__descriptor);
  return protobuf_c_message_pack_to_buffer ((const ProtobufCMessage*)message, buffer);
}
PUnspentOutputTransaction *
       punspent_output_transaction__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data)
{
  return (PUnspentOutputTransaction *)
     protobuf_c_message_unpack (&punspent_output_transaction__descriptor,
                                allocator, len, data);
}
void   punspent_output_transaction__free_unpacked
                     (PUnspentOutputTransaction *message,
                      ProtobufCAllocator *allocator)
{
  if(!message)
    return;
  assert(message->base.descriptor == &punspent_output_transaction__descriptor);
  protobuf_c_message_free_unpacked ((ProtobufCMessage*)message, allocator);
}
void   punspent_transaction__init
                     (PUnspentTransaction         *message)
{
  static const PUnspentTransaction init_value = PUNSPENT_TRANSACTION__INIT;
  *message = init_value;
}
size_t punspent_transaction__get_packed_size
                     (const PUnspentTransaction *message)
{
  assert(message->base.descriptor == &punspent_transaction__descriptor);
  return protobuf_c_message_get_packed_size ((const ProtobufCMessage*)(message));
}
size_t punspent_transaction__pack
                     (const PUnspentTransaction *message,
                      uint8_t       *out)
{
  assert(message->base.descriptor == &punspent_transaction__descriptor);
  return protobuf_c_message_pack ((const ProtobufCMessage*)message, out);
}
size_t punspent_transaction__pack_to_buffer
                     (const PUnspentTransaction *message,
                      ProtobufCBuffer *buffer)
{
  assert(message->base.descriptor == &punspent_transaction__descriptor);
  return protobuf_c_message_pack_to_buffer ((const ProtobufCMessage*)message, buffer);
}
PUnspentTransaction *
       punspent_transaction__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data)
{
  return (PUnspentTransaction *)
     protobuf_c_message_unpack (&punspent_transaction__descriptor,
                                allocator, len, data);
}
void   punspent_transaction__free_unpacked
                     (PUnspentTransaction *message,
                      ProtobufCAllocator *allocator)
{
  if(!message)
    return;
  assert(message->base.descriptor == &punspent_transaction__descriptor);
  protobuf_c_message_free_unpacked ((ProtobufCMessage*)message, allocator);
}
void   pblock__init
                     (PBlock         *message)
{
  static const PBlock init_value = PBLOCK__INIT;
  *message = init_value;
}
size_t pblock__get_packed_size
                     (const PBlock *message)
{
  assert(message->base.descriptor == &pblock__descriptor);
  return protobuf_c_message_get_packed_size ((const ProtobufCMessage*)(message));
}
size_t pblock__pack
                     (const PBlock *message,
                      uint8_t       *out)
{
  assert(message->base.descriptor == &pblock__descriptor);
  return protobuf_c_message_pack ((const ProtobufCMessage*)message, out);
}
size_t pblock__pack_to_buffer
                     (const PBlock *message,
                      ProtobufCBuffer *buffer)
{
  assert(message->base.descriptor == &pblock__descriptor);
  return protobuf_c_message_pack_to_buffer ((const ProtobufCMessage*)message, buffer);
}
PBlock *
       pblock__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data)
{
  return (PBlock *)
     protobuf_c_message_unpack (&pblock__descriptor,
                                allocator, len, data);
}
void   pblock__free_unpacked
                     (PBlock *message,
                      ProtobufCAllocator *allocator)
{
  if(!message)
    return;
  assert(message->base.descriptor == &pblock__descriptor);
  protobuf_c_message_free_unpacked ((ProtobufCMessage*)message, allocator);
}
void   pwallet__init
                     (PWallet         *message)
{
  static const PWallet init_value = PWALLET__INIT;
  *message = init_value;
}
size_t pwallet__get_packed_size
                     (const PWallet *message)
{
  assert(message->base.descriptor == &pwallet__descriptor);
  return protobuf_c_message_get_packed_size ((const ProtobufCMessage*)(message));
}
size_t pwallet__pack
                     (const PWallet *message,
                      uint8_t       *out)
{
  assert(message->base.descriptor == &pwallet__descriptor);
  return protobuf_c_message_pack ((const ProtobufCMessage*)message, out);
}
size_t pwallet__pack_to_buffer
                     (const PWallet *message,
                      ProtobufCBuffer *buffer)
{
  assert(message->base.descriptor == &pwallet__descriptor);
  return protobuf_c_message_pack_to_buffer ((const ProtobufCMessage*)message, buffer);
}
PWallet *
       pwallet__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data)
{
  return (PWallet *)
     protobuf_c_message_unpack (&pwallet__descriptor,
                                allocator, len, data);
}
void   pwallet__free_unpacked
                     (PWallet *message,
                      ProtobufCAllocator *allocator)
{
  if(!message)
    return;
  assert(message->base.descriptor == &pwallet__descriptor);
  protobuf_c_message_free_unpacked ((ProtobufCMessage*)message, allocator);
}
void   pempty__init
                     (PEmpty         *message)
{
  static const PEmpty init_value = PEMPTY__INIT;
  *message = init_value;
}
size_t pempty__get_packed_size
                     (const PEmpty *message)
{
  assert(message->base.descriptor == &pempty__descriptor);
  return protobuf_c_message_get_packed_size ((const ProtobufCMessage*)(message));
}
size_t pempty__pack
                     (const PEmpty *message,
                      uint8_t       *out)
{
  assert(message->base.descriptor == &pempty__descriptor);
  return protobuf_c_message_pack ((const ProtobufCMessage*)message, out);
}
size_t pempty__pack_to_buffer
                     (const PEmpty *message,
                      ProtobufCBuffer *buffer)
{
  assert(message->base.descriptor == &pempty__descriptor);
  return protobuf_c_message_pack_to_buffer ((const ProtobufCMessage*)message, buffer);
}
PEmpty *
       pempty__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data)
{
  return (PEmpty *)
     protobuf_c_message_unpack (&pempty__descriptor,
                                allocator, len, data);
}
void   pempty__free_unpacked
                     (PEmpty *message,
                      ProtobufCAllocator *allocator)
{
  if(!message)
    return;
  assert(message->base.descriptor == &pempty__descriptor);
  protobuf_c_message_free_unpacked ((ProtobufCMessage*)message, allocator);
}
void   psend_transaction_request__init
                     (PSendTransactionRequest         *message)
{
  static const PSendTransactionRequest init_value = PSEND_TRANSACTION_REQUEST__INIT;
  *message = init_value;
}
size_t psend_transaction_request__get_packed_size
                     (const PSendTransactionRequest *message)
{
  assert(message->base.descriptor == &psend_transaction_request__descriptor);
  return protobuf_c_message_get_packed_size ((const ProtobufCMessage*)(message));
}
size_t psend_transaction_request__pack
                     (const PSendTransactionRequest *message,
                      uint8_t       *out)
{
  assert(message->base.descriptor == &psend_transaction_request__descriptor);
  return protobuf_c_message_pack ((const ProtobufCMessage*)message, out);
}
size_t psend_transaction_request__pack_to_buffer
                     (const PSendTransactionRequest *message,
                      ProtobufCBuffer *buffer)
{
  assert(message->base.descriptor == &psend_transaction_request__descriptor);
  return protobuf_c_message_pack_to_buffer ((const ProtobufCMessage*)message, buffer);
}
PSendTransactionRequest *
       psend_transaction_request__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data)
{
  return (PSendTransactionRequest *)
     protobuf_c_message_unpack (&psend_transaction_request__descriptor,
                                allocator, len, data);
}
void   psend_transaction_request__free_unpacked
                     (PSendTransactionRequest *message,
                      ProtobufCAllocator *allocator)
{
  if(!message)
    return;
  assert(message->base.descriptor == &psend_transaction_request__descriptor);
  protobuf_c_message_free_unpacked ((ProtobufCMessage*)message, allocator);
}
void   psend_transaction_response__init
                     (PSendTransactionResponse         *message)
{
  static const PSendTransactionResponse init_value = PSEND_TRANSACTION_RESPONSE__INIT;
  *message = init_value;
}
size_t psend_transaction_response__get_packed_size
                     (const PSendTransactionResponse *message)
{
  assert(message->base.descriptor == &psend_transaction_response__descriptor);
  return protobuf_c_message_get_packed_size ((const ProtobufCMessage*)(message));
}
size_t psend_transaction_response__pack
                     (const PSendTransactionResponse *message,
                      uint8_t       *out)
{
  assert(message->base.descriptor == &psend_transaction_response__descriptor);
  return protobuf_c_message_pack ((const ProtobufCMessage*)message, out);
}
size_t psend_transaction_response__pack_to_buffer
                     (const PSendTransactionResponse *message,
                      ProtobufCBuffer *buffer)
{
  assert(message->base.descriptor == &psend_transaction_response__descriptor);
  return protobuf_c_message_pack_to_buffer ((const ProtobufCMessage*)message, buffer);
}
PSendTransactionResponse *
       psend_transaction_response__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data)
{
  return (PSendTransactionResponse *)
     protobuf_c_message_unpack (&psend_transaction_response__descriptor,
                                allocator, len, data);
}
void   psend_transaction_response__free_unpacked
                     (PSendTransactionResponse *message,
                      ProtobufCAllocator *allocator)
{
  if(!message)
    return;
  assert(message->base.descriptor == &psend_transaction_response__descriptor);
  protobuf_c_message_free_unpacked ((ProtobufCMessage*)message, allocator);
}
void   psend_block_request__init
                     (PSendBlockRequest         *message)
{
  static const PSendBlockRequest init_value = PSEND_BLOCK_REQUEST__INIT;
  *message = init_value;
}
size_t psend_block_request__get_packed_size
                     (const PSendBlockRequest *message)
{
  assert(message->base.descriptor == &psend_block_request__descriptor);
  return protobuf_c_message_get_packed_size ((const ProtobufCMessage*)(message));
}
size_t psend_block_request__pack
                     (const PSendBlockRequest *message,
                      uint8_t       *out)
{
  assert(message->base.descriptor == &psend_block_request__descriptor);
  return protobuf_c_message_pack ((const ProtobufCMessage*)message, out);
}
size_t psend_block_request__pack_to_buffer
                     (const PSendBlockRequest *message,
                      ProtobufCBuffer *buffer)
{
  assert(message->base.descriptor == &psend_block_request__descriptor);
  return protobuf_c_message_pack_to_buffer ((const ProtobufCMessage*)message, buffer);
}
PSendBlockRequest *
       psend_block_request__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data)
{
  return (PSendBlockRequest *)
     protobuf_c_message_unpack (&psend_block_request__descriptor,
                                allocator, len, data);
}
void   psend_block_request__free_unpacked
                     (PSendBlockRequest *message,
                      ProtobufCAllocator *allocator)
{
  if(!message)
    return;
  assert(message->base.descriptor == &psend_block_request__descriptor);
  protobuf_c_message_free_unpacked ((ProtobufCMessage*)message, allocator);
}
void   psend_block_response__init
                     (PSendBlockResponse         *message)
{
  static const PSendBlockResponse init_value = PSEND_BLOCK_RESPONSE__INIT;
  *message = init_value;
}
size_t psend_block_response__get_packed_size
                     (const PSendBlockResponse *message)
{
  assert(message->base.descriptor == &psend_block_response__descriptor);
  return protobuf_c_message_get_packed_size ((const ProtobufCMessage*)(message));
}
size_t psend_block_response__pack
                     (const PSendBlockResponse *message,
                      uint8_t       *out)
{
  assert(message->base.descriptor == &psend_block_response__descriptor);
  return protobuf_c_message_pack ((const ProtobufCMessage*)message, out);
}
size_t psend_block_response__pack_to_buffer
                     (const PSendBlockResponse *message,
                      ProtobufCBuffer *buffer)
{
  assert(message->base.descriptor == &psend_block_response__descriptor);
  return protobuf_c_message_pack_to_buffer ((const ProtobufCMessage*)message, buffer);
}
PSendBlockResponse *
       psend_block_response__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data)
{
  return (PSendBlockResponse *)
     protobuf_c_message_unpack (&psend_block_response__descriptor,
                                allocator, len, data);
}
void   psend_block_response__free_unpacked
                     (PSendBlockResponse *message,
                      ProtobufCAllocator *allocator)
{
  if(!message)
    return;
  assert(message->base.descriptor == &psend_block_response__descriptor);
  protobuf_c_message_free_unpacked ((ProtobufCMessage*)message, allocator);
}
static const ProtobufCFieldDescriptor pinput_transaction__field_descriptors[4] =
{
  {
    "transaction",
    1,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_BYTES,
    0,   /* quantifier_offset */
    offsetof(PInputTransaction, transaction),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "txout_index",
    2,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_INT32,
    0,   /* quantifier_offset */
    offsetof(PInputTransaction, txout_index),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "signature",
    3,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_BYTES,
    0,   /* quantifier_offset */
    offsetof(PInputTransaction, signature),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "public_key",
    4,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_BYTES,
    0,   /* quantifier_offset */
    offsetof(PInputTransaction, public_key),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
};
static const unsigned pinput_transaction__field_indices_by_name[] = {
  3,   /* field[3] = public_key */
  2,   /* field[2] = signature */
  0,   /* field[0] = transaction */
  1,   /* field[1] = txout_index */
};
static const ProtobufCIntRange pinput_transaction__number_ranges[1 + 1] =
{
  { 1, 0 },
  { 0, 4 }
};
const ProtobufCMessageDescriptor pinput_transaction__descriptor =
{
  PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC,
  "PInputTransaction",
  "PInputTransaction",
  "PInputTransaction",
  "",
  sizeof(PInputTransaction),
  4,
  pinput_transaction__field_descriptors,
  pinput_transaction__field_indices_by_name,
  1,  pinput_transaction__number_ranges,
  (ProtobufCMessageInit) pinput_transaction__init,
  NULL,NULL,NULL    /* reserved[123] */
};
static const ProtobufCFieldDescriptor poutput_transaction__field_descriptors[2] =
{
  {
    "amount",
    1,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_INT32,
    0,   /* quantifier_offset */
    offsetof(POutputTransaction, amount),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "address",
    2,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_BYTES,
    0,   /* quantifier_offset */
    offsetof(POutputTransaction, address),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
};
static const unsigned poutput_transaction__field_indices_by_name[] = {
  1,   /* field[1] = address */
  0,   /* field[0] = amount */
};
static const ProtobufCIntRange poutput_transaction__number_ranges[1 + 1] =
{
  { 1, 0 },
  { 0, 2 }
};
const ProtobufCMessageDescriptor poutput_transaction__descriptor =
{
  PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC,
  "POutputTransaction",
  "POutputTransaction",
  "POutputTransaction",
  "",
  sizeof(POutputTransaction),
  2,
  poutput_transaction__field_descriptors,
  poutput_transaction__field_indices_by_name,
  1,  poutput_transaction__number_ranges,
  (ProtobufCMessageInit) poutput_transaction__init,
  NULL,NULL,NULL    /* reserved[123] */
};
static const ProtobufCFieldDescriptor ptransaction__field_descriptors[3] =
{
  {
    "id",
    1,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_BYTES,
    0,   /* quantifier_offset */
    offsetof(PTransaction, id),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "txins",
    2,
    PROTOBUF_C_LABEL_REPEATED,
    PROTOBUF_C_TYPE_MESSAGE,
    offsetof(PTransaction, n_txins),
    offsetof(PTransaction, txins),
    &pinput_transaction__descriptor,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "txouts",
    3,
    PROTOBUF_C_LABEL_REPEATED,
    PROTOBUF_C_TYPE_MESSAGE,
    offsetof(PTransaction, n_txouts),
    offsetof(PTransaction, txouts),
    &poutput_transaction__descriptor,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
};
static const unsigned ptransaction__field_indices_by_name[] = {
  0,   /* field[0] = id */
  1,   /* field[1] = txins */
  2,   /* field[2] = txouts */
};
static const ProtobufCIntRange ptransaction__number_ranges[1 + 1] =
{
  { 1, 0 },
  { 0, 3 }
};
const ProtobufCMessageDescriptor ptransaction__descriptor =
{
  PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC,
  "PTransaction",
  "PTransaction",
  "PTransaction",
  "",
  sizeof(PTransaction),
  3,
  ptransaction__field_descriptors,
  ptransaction__field_indices_by_name,
  1,  ptransaction__number_ranges,
  (ProtobufCMessageInit) ptransaction__init,
  NULL,NULL,NULL    /* reserved[123] */
};
static const ProtobufCFieldDescriptor punspent_output_transaction__field_descriptors[3] =
{
  {
    "amount",
    1,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_INT32,
    0,   /* quantifier_offset */
    offsetof(PUnspentOutputTransaction, amount),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "address",
    2,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_BYTES,
    0,   /* quantifier_offset */
    offsetof(PUnspentOutputTransaction, address),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "spent",
    3,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_BOOL,
    0,   /* quantifier_offset */
    offsetof(PUnspentOutputTransaction, spent),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
};
static const unsigned punspent_output_transaction__field_indices_by_name[] = {
  1,   /* field[1] = address */
  0,   /* field[0] = amount */
  2,   /* field[2] = spent */
};
static const ProtobufCIntRange punspent_output_transaction__number_ranges[1 + 1] =
{
  { 1, 0 },
  { 0, 3 }
};
const ProtobufCMessageDescriptor punspent_output_transaction__descriptor =
{
  PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC,
  "PUnspentOutputTransaction",
  "PUnspentOutputTransaction",
  "PUnspentOutputTransaction",
  "",
  sizeof(PUnspentOutputTransaction),
  3,
  punspent_output_transaction__field_descriptors,
  punspent_output_transaction__field_indices_by_name,
  1,  punspent_output_transaction__number_ranges,
  (ProtobufCMessageInit) punspent_output_transaction__init,
  NULL,NULL,NULL    /* reserved[123] */
};
static const ProtobufCFieldDescriptor punspent_transaction__field_descriptors[3] =
{
  {
    "id",
    1,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_BYTES,
    0,   /* quantifier_offset */
    offsetof(PUnspentTransaction, id),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "coinbase",
    2,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_BOOL,
    0,   /* quantifier_offset */
    offsetof(PUnspentTransaction, coinbase),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "unspent_txouts",
    3,
    PROTOBUF_C_LABEL_REPEATED,
    PROTOBUF_C_TYPE_MESSAGE,
    offsetof(PUnspentTransaction, n_unspent_txouts),
    offsetof(PUnspentTransaction, unspent_txouts),
    &punspent_output_transaction__descriptor,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
};
static const unsigned punspent_transaction__field_indices_by_name[] = {
  1,   /* field[1] = coinbase */
  0,   /* field[0] = id */
  2,   /* field[2] = unspent_txouts */
};
static const ProtobufCIntRange punspent_transaction__number_ranges[1 + 1] =
{
  { 1, 0 },
  { 0, 3 }
};
const ProtobufCMessageDescriptor punspent_transaction__descriptor =
{
  PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC,
  "PUnspentTransaction",
  "PUnspentTransaction",
  "PUnspentTransaction",
  "",
  sizeof(PUnspentTransaction),
  3,
  punspent_transaction__field_descriptors,
  punspent_transaction__field_indices_by_name,
  1,  punspent_transaction__number_ranges,
  (ProtobufCMessageInit) punspent_transaction__init,
  NULL,NULL,NULL    /* reserved[123] */
};
static const ProtobufCFieldDescriptor pblock__field_descriptors[8] =
{
  {
    "version",
    1,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_INT32,
    0,   /* quantifier_offset */
    offsetof(PBlock, version),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "bits",
    2,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_INT32,
    0,   /* quantifier_offset */
    offsetof(PBlock, bits),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "previous_hash",
    3,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_BYTES,
    0,   /* quantifier_offset */
    offsetof(PBlock, previous_hash),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "hash",
    4,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_BYTES,
    0,   /* quantifier_offset */
    offsetof(PBlock, hash),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "timestamp",
    5,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_INT32,
    0,   /* quantifier_offset */
    offsetof(PBlock, timestamp),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "nonce",
    6,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_INT32,
    0,   /* quantifier_offset */
    offsetof(PBlock, nonce),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "merkle_root",
    7,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_BYTES,
    0,   /* quantifier_offset */
    offsetof(PBlock, merkle_root),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "transactions",
    9,
    PROTOBUF_C_LABEL_REPEATED,
    PROTOBUF_C_TYPE_MESSAGE,
    offsetof(PBlock, n_transactions),
    offsetof(PBlock, transactions),
    &ptransaction__descriptor,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
};
static const unsigned pblock__field_indices_by_name[] = {
  1,   /* field[1] = bits */
  3,   /* field[3] = hash */
  6,   /* field[6] = merkle_root */
  5,   /* field[5] = nonce */
  2,   /* field[2] = previous_hash */
  4,   /* field[4] = timestamp */
  7,   /* field[7] = transactions */
  0,   /* field[0] = version */
};
static const ProtobufCIntRange pblock__number_ranges[2 + 1] =
{
  { 1, 0 },
  { 9, 7 },
  { 0, 8 }
};
const ProtobufCMessageDescriptor pblock__descriptor =
{
  PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC,
  "PBlock",
  "PBlock",
  "PBlock",
  "",
  sizeof(PBlock),
  8,
  pblock__field_descriptors,
  pblock__field_indices_by_name,
  2,  pblock__number_ranges,
  (ProtobufCMessageInit) pblock__init,
  NULL,NULL,NULL    /* reserved[123] */
};
static const ProtobufCFieldDescriptor pwallet__field_descriptors[4] =
{
  {
    "secret_key",
    1,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_BYTES,
    0,   /* quantifier_offset */
    offsetof(PWallet, secret_key),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "public_key",
    2,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_BYTES,
    0,   /* quantifier_offset */
    offsetof(PWallet, public_key),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "address",
    3,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_BYTES,
    0,   /* quantifier_offset */
    offsetof(PWallet, address),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "balance",
    4,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_INT32,
    0,   /* quantifier_offset */
    offsetof(PWallet, balance),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
};
static const unsigned pwallet__field_indices_by_name[] = {
  2,   /* field[2] = address */
  3,   /* field[3] = balance */
  1,   /* field[1] = public_key */
  0,   /* field[0] = secret_key */
};
static const ProtobufCIntRange pwallet__number_ranges[1 + 1] =
{
  { 1, 0 },
  { 0, 4 }
};
const ProtobufCMessageDescriptor pwallet__descriptor =
{
  PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC,
  "PWallet",
  "PWallet",
  "PWallet",
  "",
  sizeof(PWallet),
  4,
  pwallet__field_descriptors,
  pwallet__field_indices_by_name,
  1,  pwallet__number_ranges,
  (ProtobufCMessageInit) pwallet__init,
  NULL,NULL,NULL    /* reserved[123] */
};
#define pempty__field_descriptors NULL
#define pempty__field_indices_by_name NULL
#define pempty__number_ranges NULL
const ProtobufCMessageDescriptor pempty__descriptor =
{
  PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC,
  "PEmpty",
  "PEmpty",
  "PEmpty",
  "",
  sizeof(PEmpty),
  0,
  pempty__field_descriptors,
  pempty__field_indices_by_name,
  0,  pempty__number_ranges,
  (ProtobufCMessageInit) pempty__init,
  NULL,NULL,NULL    /* reserved[123] */
};
static const ProtobufCFieldDescriptor psend_transaction_request__field_descriptors[1] =
{
  {
    "transaction",
    1,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_MESSAGE,
    0,   /* quantifier_offset */
    offsetof(PSendTransactionRequest, transaction),
    &ptransaction__descriptor,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
};
static const unsigned psend_transaction_request__field_indices_by_name[] = {
  0,   /* field[0] = transaction */
};
static const ProtobufCIntRange psend_transaction_request__number_ranges[1 + 1] =
{
  { 1, 0 },
  { 0, 1 }
};
const ProtobufCMessageDescriptor psend_transaction_request__descriptor =
{
  PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC,
  "PSendTransactionRequest",
  "PSendTransactionRequest",
  "PSendTransactionRequest",
  "",
  sizeof(PSendTransactionRequest),
  1,
  psend_transaction_request__field_descriptors,
  psend_transaction_request__field_indices_by_name,
  1,  psend_transaction_request__number_ranges,
  (ProtobufCMessageInit) psend_transaction_request__init,
  NULL,NULL,NULL    /* reserved[123] */
};
static const ProtobufCFieldDescriptor psend_transaction_response__field_descriptors[1] =
{
  {
    "transaction_id",
    1,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_BYTES,
    0,   /* quantifier_offset */
    offsetof(PSendTransactionResponse, transaction_id),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
};
static const unsigned psend_transaction_response__field_indices_by_name[] = {
  0,   /* field[0] = transaction_id */
};
static const ProtobufCIntRange psend_transaction_response__number_ranges[1 + 1] =
{
  { 1, 0 },
  { 0, 1 }
};
const ProtobufCMessageDescriptor psend_transaction_response__descriptor =
{
  PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC,
  "PSendTransactionResponse",
  "PSendTransactionResponse",
  "PSendTransactionResponse",
  "",
  sizeof(PSendTransactionResponse),
  1,
  psend_transaction_response__field_descriptors,
  psend_transaction_response__field_indices_by_name,
  1,  psend_transaction_response__number_ranges,
  (ProtobufCMessageInit) psend_transaction_response__init,
  NULL,NULL,NULL    /* reserved[123] */
};
static const ProtobufCFieldDescriptor psend_block_request__field_descriptors[1] =
{
  {
    "height",
    1,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_UINT64,
    0,   /* quantifier_offset */
    offsetof(PSendBlockRequest, height),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
};
static const unsigned psend_block_request__field_indices_by_name[] = {
  0,   /* field[0] = height */
};
static const ProtobufCIntRange psend_block_request__number_ranges[1 + 1] =
{
  { 1, 0 },
  { 0, 1 }
};
const ProtobufCMessageDescriptor psend_block_request__descriptor =
{
  PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC,
  "PSendBlockRequest",
  "PSendBlockRequest",
  "PSendBlockRequest",
  "",
  sizeof(PSendBlockRequest),
  1,
  psend_block_request__field_descriptors,
  psend_block_request__field_indices_by_name,
  1,  psend_block_request__number_ranges,
  (ProtobufCMessageInit) psend_block_request__init,
  NULL,NULL,NULL    /* reserved[123] */
};
static const ProtobufCFieldDescriptor psend_block_response__field_descriptors[1] =
{
  {
    "block",
    1,
    PROTOBUF_C_LABEL_NONE,
    PROTOBUF_C_TYPE_MESSAGE,
    0,   /* quantifier_offset */
    offsetof(PSendBlockResponse, block),
    &pblock__descriptor,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
};
static const unsigned psend_block_response__field_indices_by_name[] = {
  0,   /* field[0] = block */
};
static const ProtobufCIntRange psend_block_response__number_ranges[1 + 1] =
{
  { 1, 0 },
  { 0, 1 }
};
const ProtobufCMessageDescriptor psend_block_response__descriptor =
{
  PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC,
  "PSendBlockResponse",
  "PSendBlockResponse",
  "PSendBlockResponse",
  "",
  sizeof(PSendBlockResponse),
  1,
  psend_block_response__field_descriptors,
  psend_block_response__field_indices_by_name,
  1,  psend_block_response__number_ranges,
  (ProtobufCMessageInit) psend_block_response__init,
  NULL,NULL,NULL    /* reserved[123] */
};
static const ProtobufCMethodDescriptor pinternal__method_descriptors[2] =
{
  { "SendBlock", &psend_block_request__descriptor, &psend_block_response__descriptor },
  { "SendTransaction", &psend_transaction_request__descriptor, &psend_transaction_response__descriptor },
};
const unsigned pinternal__method_indices_by_name[] = {
  0,        /* SendBlock */
  1         /* SendTransaction */
};
const ProtobufCServiceDescriptor pinternal__descriptor =
{
  PROTOBUF_C__SERVICE_DESCRIPTOR_MAGIC,
  "PInternal",
  "PInternal",
  "PInternal",
  "",
  2,
  pinternal__method_descriptors,
  pinternal__method_indices_by_name
};
void pinternal__send_block(ProtobufCService *service,
                           const PSendBlockRequest *input,
                           PSendBlockResponse_Closure closure,
                           void *closure_data)
{
  assert(service->descriptor == &pinternal__descriptor);
  service->invoke(service, 0, (const ProtobufCMessage *) input, (ProtobufCClosure) closure, closure_data);
}
void pinternal__send_transaction(ProtobufCService *service,
                                 const PSendTransactionRequest *input,
                                 PSendTransactionResponse_Closure closure,
                                 void *closure_data)
{
  assert(service->descriptor == &pinternal__descriptor);
  service->invoke(service, 1, (const ProtobufCMessage *) input, (ProtobufCClosure) closure, closure_data);
}
void pinternal__init (PInternal_Service *service,
                      PInternal_ServiceDestroy destroy)
{
  protobuf_c_service_generated_init (&service->base,
                                     &pinternal__descriptor,
                                     (ProtobufCServiceDestroy) destroy);
}
