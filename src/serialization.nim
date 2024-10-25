import config

type
  Header* = object
    Alpha: seq[byte]
    Beta: seq[byte]
    Gamma: seq[byte]

proc initHeader*(alpha: seq[byte], beta: seq[byte], gamma: seq[byte]): Header =
  result.Alpha = alpha
  result.Beta = beta
  result.Gamma = gamma

proc getHeader*(header: Header): (seq[byte], seq[byte], seq[byte]) =
  (header.Alpha, header.Beta, header.Gamma)

proc serializeHeader*(header: Header): seq[byte] =
  assert len(header.Alpha) == alphaSize, "Alpha must be exactly " & $alphaSize & " bytes"
  assert len(header.Beta) == betaSize, "Beta must be exactly " & $betaSize & " bytes"
  assert len(header.Gamma) == gammaSize, "Gamma must be exactly " & $gammaSize & " bytes"
  result = header.Alpha & header.Beta & header.Gamma

type
  Message* = object
    Content: seq[byte]

proc initMessage*(content: seq[byte]): Message =
  result.Content = content

proc getMessage*(message: Message): seq[byte] =
  result = message.Content

proc serializeMessage*(message: Message): seq[byte] =
  assert len(message.Content) == messageSize + powSize,
      "Message with PoW must be exactly " & $(messageSize + powSize) & " bytes"
  result = newSeq[byte](k) # Prepend k bytes of zero padding
  result.add(message.Content)

proc deserializeMessage*(serializedMessage: openArray[byte]): Message =
  assert len(serializedMessage) == payloadSize,
      "Serialized message must be exactly " & $payloadSize & " bytes"
  let content = serializedMessage[k..^1]
  result.Content = content

type
  Hop* = object
    MultiAddress: seq[byte]

proc initHop*(multiAddress: seq[byte]): Hop =
  result.MultiAddress = multiAddress

proc getHop*(hop: Hop): seq[byte] =
  result = hop.MultiAddress

proc serializeHop*(hop: Hop): seq[byte] =
  assert len(hop.MultiAddress) == addrSize, "MultiAddress must be exactly " &
      $addrSize & " bytes"
  result = hop.MultiAddress

proc deserializeHop*(data: openArray[byte]): Hop =
  assert len(data) == addrSize, "MultiAddress must be exactly " & $addrSize & " bytes"
  result.MultiAddress = @(data)

type
  RoutingInfo* = object
    Addr: Hop
    Delay: seq[byte]
    Gamma: seq[byte]
    Beta: seq[byte]

proc initRoutingInfo*(address: Hop, delay: seq[byte], gamma: seq[byte],
    beta: seq[byte]): RoutingInfo =
  result.Addr = address
  result.Delay = delay
  result.Gamma = gamma
  result.Beta = beta

proc getRoutingInfo*(info: RoutingInfo): (Hop, seq[byte], seq[byte], seq[byte]) =
  (info.Addr, info.Delay, info.Gamma, info.Beta)

proc serializeRoutingInfo*(info: RoutingInfo): seq[byte] =
  let addrBytes = serializeHop(info.Addr)
  assert len(info.Delay) == delaySize, "Delay must be exactly " & $delaySize & " bytes"
  assert len(info.Gamma) == gammaSize, "Gamma must be exactly " & $gammaSize & " bytes"
  assert len(info.Beta) == (((r * (t+1)) - t) * k), "Beta must be exactly " & $(
      ((r * (t+1)) - t) * k) & " bytes"

  result = addrBytes & info.Delay & info.Gamma & info.Beta

proc deserializeRoutingInfo*(data: openArray[byte]): RoutingInfo =
  assert len(data) == betaSize + ((t + 1) * k), "Data must be exactly " & $(
      betaSize + ((t + 1) * k)) & " bytes"

  result.Addr = deserializeHop(data[0..addrSize - 1])
  result.Delay = data[addrSize..(addrSize + delaySize - 1)]
  result.Gamma = data[(addrSize + delaySize)..(addrSize + delaySize +
      gammaSize - 1)]
  result.Beta = data[(addrSize + delaySize + gammaSize)..(((r * (t+1))+t+2) * k) - 1]

type
  SphinxPacket* = object
    Hdr: Header
    Payload: seq[byte]

proc initSphinxPacket*(header: Header, payload: seq[byte]): SphinxPacket =
  result.Hdr = header
  result.Payload = payload

proc getSphinxPacket*(packet: SphinxPacket): (Header, seq[byte]) =
  (packet.Hdr, packet.Payload)

proc serializeSphinxPacket*(packet: SphinxPacket): seq[byte] =
  let headerBytes = serializeHeader(packet.Hdr)
  let payloadBytes = packet.Payload
  result = headerBytes & payloadBytes

proc deserializeSphinxPacket*(data: openArray[byte]): SphinxPacket =
  assert len(data) == packetSize, "Sphinx packet size must be exactly " &
      $packetSize & " bytes"
  result.Hdr.Alpha = data[0..(alphaSize - 1)]
  result.Hdr.Beta = data[alphaSize..(alphaSize + betaSize - 1)]
  result.Hdr.Gamma = data[(alphaSize + betaSize)..(headerSize - 1)]
  result.Payload = data[headerSize..^1]
