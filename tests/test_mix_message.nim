{.used.}

import chronicles, results, unittest
import ../mix/mix_message
import stew/byteutils

# Define test cases
suite "mix_message_tests":
  test "serialize_and_deserialize_mix_message":
    let
      message = "Hello World!"
      codec = "/test/codec/1.0.0"
      mixMsg = MixMessage.init(message.toBytes(), codec)

    let serializedResult = mixMsg.serialize()
    if serializedResult.isErr:
      error "Serialization failed", err = serializedResult.error
      fail()
    let serialized = serializedResult.get()

    let deserializedResult = MixMessage.deserialize(serialized)
    if deserializedResult.isErr:
      error "Deserialization failed", err = deserializedResult.error
      fail()
    let deserializedMsg = deserializedResult.get()

    if message != string.fromBytes(deserializedMsg.message):
      error "Deserialized message does not match the original",
        original = message, deserialized = string.fromBytes(deserializedMsg.message)
      fail()
    if codec != deserializedMsg.codec:
      error "Deserialized codec does not match the original",
        original = codec,
        deserialized = deserializedMsg.codec,
        codeco = cast[seq[byte]](codec),
        codeder = cast[seq[byte]](deserializedMsg.codec)
      fail()

  test "serialize_empty_mix_message":
    let
      emptyMessage = ""
      codec = "/test/codec/1.0.0"
      mixMsg = MixMessage.init(emptyMessage.toBytes(), codec)

    let serializedResult = mixMsg.serialize()
    if serializedResult.isErr:
      error "Serialization failed", err = serializedResult.error
      fail()
    let serialized = serializedResult.get()

    let deserializedResult = MixMessage.deserialize(serialized)
    if deserializedResult.isErr:
      error "Deserialization failed", err = deserializedResult.error
      fail()
    let dMixMsg: MixMessage = deserializedResult.get()

    if emptyMessage != string.fromBytes(dMixMsg.message):
      error "Deserialized message is not empty",
        expected = emptyMessage, actual = string.fromBytes(dMixMsg.message)
      fail()
    if codec != dMixMsg.codec:
      error "Deserialized codec does not match the original",
        original = codec, deserialized = dMixMsg.codec
      fail()

  test "serialize_and_deserialize_mix_message_and_destination":
    let
      message = "Hello World!"
      codec = "/test/codec/1.0.0"
      destination =
        "/ip4/0.0.0.0/tcp/4242/p2p/16Uiu2HAmFkwLVsVh6gGPmSm9R3X4scJ5thVdKfWYeJsKeVrbcgVC"
      mixMsg = MixMessage.init(message.toBytes(), codec)

    let serializedResult = mixMsg.serializeWithDestination(destination)
    if serializedResult.isErr:
      error "Serialization with destination failed", err = serializedResult.error
      fail()
    let serialized = serializedResult.get()

    let deserializedResult = MixMessage.deserializeWithDestination(serialized)
    if deserializedResult.isErr:
      error "Deserialization with destination failed", err = deserializedResult.error
      fail()
    let (dMixMessage, dDest) = deserializedResult.get()

    if message != string.fromBytes(dMixMessage.message):
      error "Deserialized message does not match the original",
        original = message, deserialized = string.fromBytes(dMixMessage.message)
      fail()
    if codec != dMixMessage.codec:
      error "Deserialized codec does not match the original",
        original = codec, deserialized = dMixMessage.codec
      fail()
    if destination != dDest:
      error "Deserialized destination does not match the original",
        original = destination, deserialized = dDest
      fail()
