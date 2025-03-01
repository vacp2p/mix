import chronicles, results, unittest
import ../src/[config, pow, serialization]

# Define test cases
suite "serialization_tests":
  test "serialize_and_deserialize_header":
    let header = initHeader(
      newSeq[byte](alphaSize), newSeq[byte](betaSize), newSeq[byte](gammaSize)
    )

    let serializedRes = serializeHeader(header)
    if serializedRes.isErr:
      error "Failed to serialize header", err = serializedRes.error
      fail()
    let serialized = serializedRes.get()

    if len(serialized) != headerSize:
      error "Serialized header size is incorrect",
        expected = headerSize, actual = len(serialized)
      fail()

  test "serialize_and_deserialize_message":
    let message = initMessage(newSeq[byte](messageSize))

    let powRes = attachPow(getMessage(message))
    if powRes.isErr:
      error "Proof of work generation error."
      fail()
    let pow = powRes.get()

    let msgPow = initMessage(pow)

    let serializedRes = serializeMessage(msgPow)
    if serializedRes.isErr:
      error "Failed to serialize message", err = serializedRes.error
      fail()
    let serialized = serializedRes.get()

    let deserializedRes = deserializeMessage(serialized)
    if deserializedRes.isErr:
      error "Failed to deserialize message", err = deserializedRes.error
      fail()
    let deserialized = deserializedRes.get()

    if getMessage(msgPow) != getMessage(deserialized):
      error "Deserialized message does not match the original message"
      fail()

  test "serialize_and_deserialize_hop":
    let hop = initHop(newSeq[byte](addrSize))

    let serializedRes = serializeHop(hop)
    if serializedRes.isErr:
      error "Failed to serialize hop", err = serializedRes.error
      fail()
    let serialized = serializedRes.get()

    let deserializedRes = deserializeHop(serialized)
    if deserializedRes.isErr:
      error "Failed to deserialize hop", err = deserializedRes.error
      fail()
    let deserialized = deserializedRes.get()

    if getHop(hop) != getHop(deserialized):
      error "Deserialized multiaddress does not match the original multiaddress"
      fail()

  test "serialize_and_deserialize_routing_info":
    let routingInfo = initRoutingInfo(
      initHop(newSeq[byte](addrSize)),
      newSeq[byte](delaySize),
      newSeq[byte](gammaSize),
      newSeq[byte](((r * (t + 1)) - t) * k),
    )

    let serializedRes = serializeRoutingInfo(routingInfo)
    if serializedRes.isErr:
      error "Failed to serialize routing info", err = serializedRes.error
      fail()
    let serialized = serializedRes.get()

    let
      suffixLength = (t + 1) * k
      suffix = newSeq[byte](suffixLength)

    let deserializedRes = deserializeRoutingInfo(serialized & suffix)
    if deserializedRes.isErr:
      error "Failed to deserialize routing info", err = deserializedRes.error
      fail()
    let deserialized = deserializedRes.get()

    let
      (hop, delay, gamma, beta) = getRoutingInfo(routingInfo)
      (dHop, dDelay, dGamma, dBeta) = getRoutingInfo(deserialized)

    if getHop(hop) != getHop(dHop):
      error "Deserialized multiaddress does not match the original multiaddress"
      fail()

    if delay != dDelay:
      error "Deserialized delay does not match the original delay"
      fail()

    if gamma != dGamma:
      error "Deserialized gamma does not match the original gamma"
      fail()

    if beta != dBeta[0 .. (((r * (t + 1)) - t) * k) - 1]:
      error "Deserialized beta does not match the original beta"
      fail()

  test "serialize_and_deserialize_sphinx_packet":
    let
      header = initHeader(
        newSeq[byte](alphaSize), newSeq[byte](betaSize), newSeq[byte](gammaSize)
      )
      payload = newSeq[byte](payloadSize)
      packet = initSphinxPacket(header, payload)

    let serializedRes = serializeSphinxPacket(packet)
    if serializedRes.isErr:
      error "Failed to serialize sphinx packet", err = serializedRes.error
      fail()
    let serialized = serializedRes.get()

    let deserializedRes = deserializeSphinxPacket(serialized)
    if deserializedRes.isErr:
      error "Failed to deserialize sphinx packet", err = deserializedRes.error
      fail()
    let deserialized = deserializedRes.get()

    let
      (dHeader, dPayload) = getSphinxPacket(deserialized)
      (alpha, beta, gamma) = getHeader(header)
      (dAlpha, dBeta, dGamma) = getHeader(dHeader)

    if alpha != dAlpha:
      error "Deserialized alpha does not match the original alpha"
      fail()

    if beta != dBeta:
      error "Deserialized beta does not match the original beta"
      fail()

    if gamma != dGamma:
      error "Deserialized gamma does not match the original gamma"
      fail()

    if payload != dPayload:
      error "Deserialized payload does not match the original payload"
      fail()
