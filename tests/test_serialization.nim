import config
import ../src/serialization
import unittest

# Define test cases
suite "Serialization Tests":

  test "Serialize and Deserialize Header":
    let header = initHeader(
      newSeq[byte](alphaSize),
      newSeq[byte](betaSize),
      newSeq[byte](gammaSize)
    )
    let serialized = serializeHeader(header)
    assert len(serialized) == headerSize, "Serialized header size is incorrect"

  test "Serialize and Deserialize Message":
    let message = initMessage(newSeq[byte](messageSize))
    let serialized = serializeMessage(message)
    let deserialized = deserializeMessage(serialized)
    assert getMessage(message) == getMessage(deserialized), "Deserialized message does not match the original message"

  test "Serialize and Deserialize Hop":
    let hop = initHop(newSeq[byte](addrSize))
    let serialized = serializeHop(hop)
    let deserialized = deserializeHop(serialized)
    assert getHop(hop) == getHop(deserialized), "Deserialized multiaddress does not match the original multiaddress"

  test "Serialize and Deserialize RoutingInfo":
    let routingInfo = initRoutingInfo(
      initHop(newSeq[byte](addrSize)),
      newSeq[byte](delaySize),
      newSeq[byte](gammaSize),
      newSeq[byte](((2 * r) - 1) * k)
    )
    let serialized = serializeRoutingInfo(routingInfo)
    let deserialized = deserializeRoutingInfo(serialized)
    let (hop, delay, gamma, beta) = getRoutingInfo(routingInfo)
    let (dHop, dDelay, dGamma, dBeta) = getRoutingInfo(deserialized)

    assert getHop(hop) == getHop(dHop), "Deserialized multiaddress does not match the original multiaddress"
    assert delay == dDelay, "Deserialized delay does not match the original delay"
    assert gamma == dGamma, "Deserialized gamma does not match the original gamma"
    assert beta == dBeta, "Deserialized beta does not match the original beta"

  test "Serialize and Deserialize SphinxPacket":
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
    let (dAlpha, dBeta, dGamma) = getHeader(header)

    assert alpha == dAlpha, "Deserialized alpha does not match the original alpha"
    assert beta == dBeta, "Deserialized beta does not match the original beta"
    assert gamma == dGamma, "Deserialized gamma does not match the original gammaa"
    assert payload == dPayload, "Deserialized payload does not match the original payload"
