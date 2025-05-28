import chronicles, results
import ./[config, protocol, utils]

type MixMessage* = object
  message*: seq[byte]
  protocol*: ProtocolType

proc initMixMessage*(message: openArray[byte], protocol: ProtocolType): MixMessage =
  return MixMessage(message: @message, protocol: protocol)

proc serializeMixMessage*(mixMsg: MixMessage): Result[seq[byte], string] =
  try:
    let
      msgBytes = mixMsg.message
      protocolBytes = uint16ToBytes(uint16(mixMsg.protocol))
    return ok(msgBytes & protocolBytes)
  except Exception as e:
    error "Failed to serialize MixMessage", err = e.msg
    return err("Serialization failed: " & e.msg)

proc deserializeMixMessage*(data: openArray[byte]): Result[MixMessage, string] =
  try:
    let message = data[0 ..^ (protocolTypeSize + 1)]

    let res = bytesToUInt16(data[^protocolTypeSize ..^ 1])
    if res.isErr:
      return err(res.error)
    let protocol = ProtocolType(res.get())

    return ok(MixMessage(message: message, protocol: protocol))
  except Exception as e:
    error "Failed to deserialize MixMessage", err = e.msg
    return err("Deserialization failed: " & e.msg)

proc serializeMixMessageAndDestination*(
    mixMsg: MixMessage, dest: string
): Result[seq[byte], string] =
  try:
    let
      msgBytes = mixMsg.message
      protocolBytes = uint16ToBytes(uint16(mixMsg.protocol))

    let destBytes = multiAddrToBytes(dest).valueOr:
      return err("Error in multiaddress conversion to bytes: " & error)

    if len(destBytes) != addrSize:
      error "Destination address must be exactly " & $addrSize & " bytes"
      return err("Destination address must be exactly " & $addrSize & " bytes")

    return ok(msgBytes & protocolBytes & destBytes)
  except Exception as e:
    error "Failed to serialize MixMessage and destination", err = e.msg
    return err("Serialization with destination failed: " & e.msg)

proc deserializeMixMessageAndDestination*(
    data: openArray[byte]
): Result[(seq[byte], string), string] =
  try:
    let mixMsg = data[0 ..^ (addrSize + 1)]

    let dest = bytesToMultiAddr(data[^addrSize ..^ 1]).valueOr:
      return err("Error in destination multiaddress conversion to bytes: " & error)

    return ok((mixMsg, dest))
  except Exception as e:
    return err("Deserialization with destination failed: " & e.msg)
