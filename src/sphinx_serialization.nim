import results
import ./mixproto_config

type Header* = object
  Alpha: seq[byte]
  Beta: seq[byte]
  Gamma: seq[byte]

proc initHeader*(alpha: seq[byte], beta: seq[byte], gamma: seq[byte]): Header =
  return Header(Alpha: alpha, Beta: beta, Gamma: gamma)

proc getHeader*(header: Header): (seq[byte], seq[byte], seq[byte]) =
  (header.Alpha, header.Beta, header.Gamma)

proc serializeHeader*(header: Header): Result[seq[byte], string] =
  if len(header.Alpha) != alphaSize:
    return err("Alpha must be exactly " & $alphaSize & " bytes")
  if len(header.Beta) != betaSize:
    return err("Beta must be exactly " & $betaSize & " bytes")
  if len(header.Gamma) != gammaSize:
    return err("Gamma must be exactly " & $gammaSize & " bytes")
  return ok(header.Alpha & header.Beta & header.Gamma)

type Message* = object
  Content: seq[byte]

proc initMessage*(content: seq[byte]): Message =
  return Message(Content: content)

proc getMessage*(message: Message): seq[byte] =
  return message.Content

proc serializeMessage*(message: Message): Result[seq[byte], string] =
  if len(message.Content) != messageSize:
    return err("Message must be exactly " & $(messageSize) & " bytes")
  var res = newSeq[byte](k) # Prepend k bytes of zero padding
  res.add(message.Content)
  return ok(res)

proc deserializeMessage*(serializedMessage: openArray[byte]): Result[Message, string] =
  if len(serializedMessage) != payloadSize:
    return err("Serialized message must be exactly " & $payloadSize & " bytes")
  let content = serializedMessage[k ..^ 1]
  return ok(Message(Content: content))

type Hop* = object
  MultiAddress: seq[byte]

proc initHop*(multiAddress: seq[byte]): Hop =
  return Hop(MultiAddress: multiAddress)

proc getHop*(hop: Hop): seq[byte] =
  return hop.MultiAddress

proc serializeHop*(hop: Hop): Result[seq[byte], string] =
  if len(hop.MultiAddress) != addrSize:
    return err("MultiAddress must be exactly " & $addrSize & " bytes")
  return ok(hop.MultiAddress)

proc deserializeHop*(data: openArray[byte]): Result[Hop, string] =
  if len(data) != addrSize:
    return err("MultiAddress must be exactly " & $addrSize & " bytes")
  return ok(Hop(MultiAddress: @data))

type RoutingInfo* = object
  Addr: Hop
  Delay: seq[byte]
  Gamma: seq[byte]
  Beta: seq[byte]

proc initRoutingInfo*(
    address: Hop, delay: seq[byte], gamma: seq[byte], beta: seq[byte]
): RoutingInfo =
  return RoutingInfo(Addr: address, Delay: delay, Gamma: gamma, Beta: beta)

proc getRoutingInfo*(info: RoutingInfo): (Hop, seq[byte], seq[byte], seq[byte]) =
  (info.Addr, info.Delay, info.Gamma, info.Beta)

proc serializeRoutingInfo*(info: RoutingInfo): Result[seq[byte], string] =
  if len(info.Delay) != delaySize:
    return err("Delay must be exactly " & $delaySize & " bytes")
  if len(info.Gamma) != gammaSize:
    return err("Gamma must be exactly " & $gammaSize & " bytes")
  if len(info.Beta) != (((r * (t + 1)) - t) * k):
    return err("Beta must be exactly " & $(((r * (t + 1)) - t) * k) & " bytes")

  let addrBytes = serializeHop(info.Addr).valueOr:
    return err("Serialize hop error: " & error)

  return ok(addrBytes & info.Delay & info.Gamma & info.Beta)

proc deserializeRoutingInfo*(data: openArray[byte]): Result[RoutingInfo, string] =
  if len(data) != betaSize + ((t + 1) * k):
    return err("Data must be exactly " & $(betaSize + ((t + 1) * k)) & " bytes")

  let hopRes = deserializeHop(data[0 .. addrSize - 1]).valueOr:
    return err("Deserialize hop error: " & error)

  return ok(
    RoutingInfo(
      Addr: hopRes,
      Delay: data[addrSize .. (addrSize + delaySize - 1)],
      Gamma: data[(addrSize + delaySize) .. (addrSize + delaySize + gammaSize - 1)],
      Beta:
        data[(addrSize + delaySize + gammaSize) .. (((r * (t + 1)) + t + 2) * k) - 1],
    )
  )

type SphinxPacket* = object
  Hdr: Header
  Payload: seq[byte]

proc initSphinxPacket*(header: Header, payload: seq[byte]): SphinxPacket =
  return SphinxPacket(Hdr: header, Payload: payload)

proc getSphinxPacket*(packet: SphinxPacket): (Header, seq[byte]) =
  (packet.Hdr, packet.Payload)

proc serializeSphinxPacket*(packet: SphinxPacket): Result[seq[byte], string] =
  let headerBytes = serializeHeader(packet.Hdr).valueOr:
    return err("Serialize sphinx packet header error: " & error)

  return ok(headerBytes & packet.Payload)

proc deserializeSphinxPacket*(data: openArray[byte]): Result[SphinxPacket, string] =
  if len(data) != packetSize:
    return err("Sphinx packet size must be exactly " & $packetSize & " bytes")

  let header = Header(
    Alpha: data[0 .. (alphaSize - 1)],
    Beta: data[alphaSize .. (alphaSize + betaSize - 1)],
    Gamma: data[(alphaSize + betaSize) .. (headerSize - 1)],
  )

  return ok(SphinxPacket(Hdr: header, Payload: data[headerSize ..^ 1]))
