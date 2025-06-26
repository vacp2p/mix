import chronicles, results, unittest
import ../mix/[mix_message, protocol]

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

    if message != cast[string](deserializedMsg.message):
      error "Deserialized message does not match the original",
        original = message, deserialized = cast[string](deserializedMsg.message)
      fail()
    if protocol != deserializedMsg.protocol:
      error "Deserialized protocol does not match the original",
        original = protocol, deserialized = deserializedMsg.protocol
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
    let dMixMsg: MixMessage = deserializedResult.get()

    if emptyMessage != cast[string](dMixMsg.message):
      error "Deserialized message is not empty",
        expected = emptyMessage, actual = cast[string](dMixMsg.message)
      fail()
    if protocol != dMixMsg.protocol:
      error "Deserialized protocol does not match the original",
        original = protocol, deserialized = dMixMsg.protocol
      fail()

  test "serialize_and_deserialize_mix_message_and_destination":
    let
      message = "Hello World!"
      protocol = ProtocolType.GossipSub12
      destination =
        "/ip4/0.0.0.0/tcp/4242/p2p/16Uiu2HAmFkwLVsVh6gGPmSm9R3X4scJ5thVdKfWYeJsKeVrbcgVC"
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

    if message != cast[string](dMixMsg.message):
      error "Deserialized message does not match the original",
        original = message, deserialized = cast[string](dMixMsg.message)
      fail()
    if protocol != dMixMsg.protocol:
      error "Deserialized protocol does not match the original",
        original = protocol, deserialized = dMixMsg.protocol
      fail()
    if destination != dDest:
      error "Deserialized destination does not match the original",
        original = destination, deserialized = dDest
      fail()
