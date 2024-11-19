import config, utils

const protocolTypeSize* = 2

type
  ProtocolType* = enum
    Ping = 0,         # Represents the Ping protocol
    GossipSub = 1,    # Represents the GossipSub protocol
    OtherProtocol = 2 # Placeholder for other protocols

type
  MixMessage* = object
    message: seq[byte]
    protocol: ProtocolType

proc initMixMessage*(message: openArray[byte], protocol: ProtocolType): MixMessage =
  result.message = @message
  result.protocol = protocol

proc getMixMessage*(mixMsg: MixMessage): (seq[byte], ProtocolType) =
  (mixMsg.message, mixMsg.protocol)

proc serializeMixMessage*(mixMsg: MixMessage): seq[byte] =
  let msgBytes = mixMsg.message
  let protocolBytes = uint16ToBytes(uint16(mixMsg.protocol))
  result = msgBytes & protocolBytes

proc deserializeMixMessage*(data: openArray[byte]): MixMessage =
  result.message = data[0..^(protocolTypeSize+1)]
  result.protocol = ProtocolType(bytesToUInt16(data[^protocolTypeSize..^1]))

proc serializeMixMessageAndDestination*(mixMsg: MixMessage, dest: string): seq[byte] =
  let msgBytes = mixMsg.message
  let protocolBytes = uint16ToBytes(uint16(mixMsg.protocol))
  let destBytes = multiAddrToBytes(dest)
  assert len(destBytes) == addrSize, "Destination address must be exactly " &
      $addrSize & " bytes"

  result = msgBytes & protocolBytes & destBytes

proc deserializeMixMessageAndDestination*(data: openArray[byte]): (seq[byte], string) =
  let mixMsg = data[0..^(addrSize + 1)]
  let dest = bytesToMultiAddr(data[^addrSize..^1])

  return (mixMsg, dest)
