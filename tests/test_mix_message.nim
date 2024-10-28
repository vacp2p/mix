import ../src/mix_message
import unittest

# Define test cases
suite "mix_message_tests":

  test "serialize_and_deserialize_mix_message":
    let message = "Hello World!"
    let protocol = ProtocolType.Ping
    let mixMsg = initMixMessage(message, protocol)

    let serialized = serializeMixMessage(mixMsg)

    let deserializedMsg = deserializeMixMessage(serialized)

    let (dMessage, dProtocol) = getMixMessage(deserializedMsg)
    assert message == dMessage, "Deserialized message does not match the original"
    assert protocol == dProtocol, "Deserialized protocol does not match the original"

  test "serialize_empty_mix_message":
    let emptyMessage = ""
    let protocol = ProtocolType.OtherProtocol
    let mixMsg = initMixMessage(emptyMessage, protocol)

    let serialized = serializeMixMessage(mixMsg)

    let dMixMsg = deserializeMixMessage(serialized)

    let (dMessage, dProtocol) = getMixMessage(dMixMsg)
    assert emptyMessage == dMessage, "Deserialized message is not empty"
    assert protocol == dProtocol, "Deserialized protocol does not match the original"

  test "serialize_and_deserialize_mix_message_and_destination":
    let message = "Hello World!"
    let protocol = ProtocolType.GossipSub
    let destination = "/ip4/127.0.0.1/tcp/4242/p2p/16Uiu2HAmFkwLVsVh6gGPmSm9R3X4scJ5thVdKfWYeJsKeVrbcgVC"
    let mixMsg = initMixMessage(message, protocol)

    let serialized = serializeMixMessageAndDestination(mixMsg, destination)

    let (mixMsgBytes, dDest) = deserializeMixMessageAndDestination(serialized)

    let dMixMsg = deserializeMixMessage(mixMsgBytes)

    let (dMessage, dProtocol) = getMixMessage(dMixMsg)
    assert message == dMessage, "Deserialized message does not match the original"
    assert protocol == dProtocol, "Deserialized protocol does not match the original"
    assert destination == dDest, "Deserialized destination does not match the original"
