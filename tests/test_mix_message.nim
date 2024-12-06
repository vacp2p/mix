import ../src/mix_message
import chronicles, results, unittest

# Define test cases
suite "mix_message_tests":

  test "serialize_and_deserialize_mix_message":
    let
      message = "Hello World!"
      protocol = ProtocolType.Ping
      mixMsg = initMixMessage(cast[seq[byte]](message), protocol)

    let serializedResult = serializeMixMessage(mixMsg)
    if serializedResult.isErr:
      error "Serialization failed", err = serializedResult.error
      fail()
    let serialized = serializedResult.get()

    let deserializedResult = deserializeMixMessage(serialized)
    if deserializedResult.isErr:
      error "Deserialization failed", err = deserializedResult.error
      fail()
    let deserializedMsg = deserializedResult.get()

    let (dMessage, dProtocol) = getMixMessage(deserializedMsg)
    if message != cast[string](dMessage):
      error "Deserialized message does not match the original",
            original = message,
            deserialized = cast[string](dMessage)
      fail()
    if protocol != dProtocol:
      error "Deserialized protocol does not match the original",
            original = protocol,
            deserialized = dProtocol
      fail()

  test "serialize_empty_mix_message":
    let
      emptyMessage = ""
      protocol = ProtocolType.OtherProtocol
      mixMsg = initMixMessage(cast[seq[byte]](emptyMessage), protocol)

    let serializedResult = serializeMixMessage(mixMsg)
    if serializedResult.isErr:
      error "Serialization failed", err = serializedResult.error
      fail()
    let serialized = serializedResult.get()

    let deserializedResult = deserializeMixMessage(serialized)
    if deserializedResult.isErr:
      error "Deserialization failed", err = deserializedResult.error
      fail()
    let dMixMsg = deserializedResult.get()

    let (dMessage, dProtocol) = getMixMessage(dMixMsg)
    if emptyMessage != cast[string](dMessage):
      error "Deserialized message is not empty",
            expected = emptyMessage,
            actual = cast[string](dMessage)
      fail()
    if protocol != dProtocol:
      error "Deserialized protocol does not match the original",
            original = protocol,
            deserialized = dProtocol
      fail()

  test "serialize_and_deserialize_mix_message_and_destination":
    let
      message = "Hello World!"
      protocol = ProtocolType.GossipSub
      destination = "/ip4/127.0.0.1/tcp/4242/mix/16Uiu2HAmFkwLVsVh6gGPmSm9R3X4scJ5thVdKfWYeJsKeVrbcgVC"
      mixMsg = initMixMessage(cast[seq[byte]](message), protocol)

    let serializedResult = serializeMixMessageAndDestination(mixMsg, destination)
    if serializedResult.isErr:
      error "Serialization with destination failed", err = serializedResult.error
      fail()
    let serialized = serializedResult.get()

    let deserializedResult = deserializeMixMessageAndDestination(serialized)
    if deserializedResult.isErr:
      error "Deserialization with destination failed", err = deserializedResult.error
      fail()
    let (mixMsgBytes, dDest) = deserializedResult.get()

    let dMixMsgResult = deserializeMixMessage(mixMsgBytes)
    if dMixMsgResult.isErr:
      error "Deserialization of MixMessage failed", err = dMixMsgResult.error
      fail()
    let dMixMsg = dMixMsgResult.get()

    let (dMessage, dProtocol) = getMixMessage(dMixMsg)
    if message != cast[string](dMessage):
      error "Deserialized message does not match the original",
            original = message,
            deserialized = cast[string](dMessage)
      fail()
    if protocol != dProtocol:
      error "Deserialized protocol does not match the original",
            original = protocol,
            deserialized = dProtocol
      fail()
    if destination != dDest:
      error "Deserialized destination does not match the original",
            original = destination,
            deserialized = dDest
      fail()