import ../src/config, ../src/pow
import ../src/serialization
import unittest

# Define test cases
suite "serialization_tests":

  test "serialize_and_deserialize_header":
    let header = initHeader(
      newSeq[byte](alphaSize),
      newSeq[byte](betaSize),
      newSeq[byte](gammaSize)
    )
    let serialized = serializeHeader(header)
    assert len(serialized) == headerSize, "Serialized header size is incorrect"

  test "serialize_and_deserialize_message":
    let message = initMessage(newSeq[byte](messageSize))
    let msgPow = initMessage(attachPow(getMessage(message)))
    let serialized = serializeMessage(msgPow)
    let deserialized = deserializeMessage(serialized)
    assert getMessage(msgPow) == getMessage(deserialized), "Deserialized message does not match the original message"

  test "serialize_and_deserialize_hop":
    let hop = initHop(newSeq[byte](addrSize))
    let serialized = serializeHop(hop)
    let deserialized = deserializeHop(serialized)
    assert getHop(hop) == getHop(deserialized), "Deserialized multiaddress does not match the original multiaddress"

  test "serialize_and_deserialize_routing_info":
    let routingInfo = initRoutingInfo(
      initHop(newSeq[byte](addrSize)),
      newSeq[byte](delaySize),
      newSeq[byte](gammaSize),
      newSeq[byte](((r * (t+1)) - t) * k)
    )
    let serialized = serializeRoutingInfo(routingInfo)
    let suffixLength = (t + 1) * k
    let suffix = newSeq[byte](suffixLength)
    let deserialized = deserializeRoutingInfo(serialized & suffix)
    let (hop, delay, gamma, beta) = getRoutingInfo(routingInfo)
    let (dHop, dDelay, dGamma, dBeta) = getRoutingInfo(deserialized)

    assert getHop(hop) == getHop(dHop), "Deserialized multiaddress does not match the original multiaddress"
    assert delay == dDelay, "Deserialized delay does not match the original delay"
    assert gamma == dGamma, "Deserialized gamma does not match the original gamma"
    assert beta == dBeta[0..(((r * (t+1)) - t) * k) - 1], "Deserialized beta does not match the original beta"

  test "serialize_and_deserialize_sphinx_packet":
    let header = initHeader(
      newSeq[byte](alphaSize),
      newSeq[byte](betaSize),
      newSeq[byte](gammaSize)
    )
    let payload = newSeq[byte](payloadSize)
    let packet = initSphinxPacket(header, payload)
    let serialized = serializeSphinxPacket(packet)
    let deserialized = deserializeSphinxPacket(serialized)

    let (dHeader, dPayload)  = getSphinxPacket(deserialized)

    let (alpha, beta, gamma) = getHeader(header)
    let (dAlpha, dBeta, dGamma) = getHeader(dHeader)

    assert alpha == dAlpha, "Deserialized alpha does not match the original alpha"
    assert beta == dBeta, "Deserialized beta does not match the original beta"
    assert gamma == dGamma, "Deserialized gamma does not match the original gammaa"
    assert payload == dPayload, "Deserialized payload does not match the original payload"