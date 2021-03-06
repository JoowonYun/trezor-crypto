/* Generated by the protocol buffer compiler.  DO NOT EDIT! */
/* Generated from: hyconTx.proto */

#ifndef PROTOBUF_C_hyconTx_2eproto__INCLUDED
#define PROTOBUF_C_hyconTx_2eproto__INCLUDED

#include <protobuf-c/protobuf-c.h>

PROTOBUF_C__BEGIN_DECLS

#if PROTOBUF_C_VERSION_NUMBER < 1003000
# error This file was generated by a newer version of protoc-c which is incompatible with your libprotobuf-c headers. Please update your headers.
#elif 1003001 < PROTOBUF_C_MIN_COMPILER_VERSION
# error This file was generated by an older version of protoc-c which is incompatible with your libprotobuf-c headers. Please regenerate this file with a newer version of protoc-c.
#endif


typedef struct _HyconTxs HyconTxs;
typedef struct _HyconTx HyconTx;


/* --- enums --- */


/* --- messages --- */

struct  _HyconTxs
{
  ProtobufCMessage base;
  size_t n_txs;
  HyconTx **txs;
};
#define HYCON_TXS__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&hycon_txs__descriptor) \
    , 0,NULL }


struct  _HyconTx
{
  ProtobufCMessage base;
  /*
   * Consensus Critical
   */
  /*
   *Address
   */
  ProtobufCBinaryData from;
  /*
   *Address
   */
  ProtobufCBinaryData to;
  uint64_t amount;
  uint64_t fee;
  uint32_t nonce;
  ProtobufCBinaryData signature;
  uint32_t recovery;
};
#define HYCON_TX__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&hycon_tx__descriptor) \
    , {0,NULL}, {0,NULL}, 0, 0, 0, {0,NULL}, 0 }


/* HyconTxs methods */
void   hycon_txs__init
                     (HyconTxs         *message);
size_t hycon_txs__get_packed_size
                     (const HyconTxs   *message);
size_t hycon_txs__pack
                     (const HyconTxs   *message,
                      uint8_t             *out);
size_t hycon_txs__pack_to_buffer
                     (const HyconTxs   *message,
                      ProtobufCBuffer     *buffer);
HyconTxs *
       hycon_txs__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   hycon_txs__free_unpacked
                     (HyconTxs *message,
                      ProtobufCAllocator *allocator);
/* HyconTx methods */
void   hycon_tx__init
                     (HyconTx         *message);
size_t hycon_tx__get_packed_size
                     (const HyconTx   *message);
size_t hycon_tx__pack
                     (const HyconTx   *message,
                      uint8_t             *out);
size_t hycon_tx__pack_to_buffer
                     (const HyconTx   *message,
                      ProtobufCBuffer     *buffer);
HyconTx *
       hycon_tx__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   hycon_tx__free_unpacked
                     (HyconTx *message,
                      ProtobufCAllocator *allocator);
/* --- per-message closures --- */

typedef void (*HyconTxs_Closure)
                 (const HyconTxs *message,
                  void *closure_data);
typedef void (*HyconTx_Closure)
                 (const HyconTx *message,
                  void *closure_data);

/* --- services --- */


/* --- descriptors --- */

extern const ProtobufCMessageDescriptor hycon_txs__descriptor;
extern const ProtobufCMessageDescriptor hycon_tx__descriptor;

PROTOBUF_C__END_DECLS


#endif  /* PROTOBUF_C_hyconTx_2eproto__INCLUDED */
