import results, strutils
import stew/base58
import ./config

const addrBytesSize* = 46

proc bytesToUInt16*(data: openArray[byte]): Result[uint16, string] =
  if len(data) != 2:
    return err("Data must be exactly 2 bytes long to convert to uint16")
  return ok(uint16(data[0]) shl 8 or uint16(data[1]))

proc uint16ToBytes*(value: uint16): seq[byte] =
  return @[byte(value shr 8), byte(value and 0xFF)]

proc bytesToUInt32*(data: openArray[byte]): Result[uint32, string] =
  if len(data) != 4:
    return err("Data must be exactly 4 bytes long to convert to uint32")
  return ok(
    uint32(data[0]) shl 24 or uint32(data[1]) shl 16 or uint32(data[2]) shl 8 or
      uint32(data[3])
  )

proc uint32ToBytes*(value: uint32): seq[byte] =
  return
    @[
      byte(value shr 24),
      byte(value shr 16 and 0xFF),
      byte(value shr 8 and 0xFF),
      byte(value and 0xFF),
    ]

proc multiAddrToBytes*(multiAddr: string): Result[seq[byte], string] =
  var
    parts = multiAddr.split('/')
    res: seq[byte] = @[]

  if parts.len != 7:
    return err("Invalid multiaddress format")

  # IP address (4 bytes) ToDo: Add support for ipv6. Supporting ipv4 only for testing purposes
  let ipParts = parts[2].split('.')
  if ipParts.len != 4:
    return err("Invalid IP address format")
  for part in ipParts:
    try:
      let ipPart = parseInt(part)
      if ipPart < 0 or ipPart > 255:
        return err("Invalid IP address format")
      res.add(byte(ipPart))
    except ValueError:
      return err("Invalid IP address format")

  # Protocol (1 byte) ToDo: TLS or QUIC
  if parts[3] != "tcp" and parts[3] != "quic":
    return err("Unsupported protocol")
  res.add(
    if parts[3] == "tcp":
      byte(0)
    else:
      byte(1)
  ) # Using TCP for testing purposes

  # Port (2 bytes)
  try:
    let port = parseInt(parts[4])
    if port < 0 or port > 65535:
      return err("Invalid port")
    res.add(uint16ToBytes(uint16(port)))
  except ValueError:
    return err("Invalid port")

  # PeerID (39 bytes)
  let peerIdBase58 = parts[6]
  if peerIdBase58.len != 53:
    return err("Peer ID must be exactly 53 characters")
  try:
    let peerIdBytes = Base58.decode(peerIdBase58)
    if peerIdBytes.len != 39:
      return err("Peer ID must be exactly 39 bytes")
    res.add(peerIdBytes)
  except Base58Error:
    return err("Invalid Peer ID")

  if res.len != ADDR_SIZE:
    return err("Address must be exactly " & $ADDR_SIZE & " bytes")

  return ok(res)

proc bytesToMultiAddr*(bytes: openArray[byte]): Result[string, string] =
  if bytes.len != ADDR_SIZE:
    return err("Address must be exactly " & $ADDR_SIZE & " bytes")

  var ipParts: seq[string] = @[]
  for i in 0 .. 3:
    ipParts.add($bytes[i])
      # ToDo: Add support for ipv6. Supporting ipv4 only for testing purposes

  let protocol = if bytes[4] == 0: "tcp" else: "quic"
    # ToDo: TLS or QUIC (Using TCP for testing purposes)

  let port = bytesToUInt16(bytes[5 .. 6]).valueOr:
    return err("Error in conversion of bytes to port no.: " & error)

  let peerIdBase58 = Base58.encode(bytes[7 ..^ 1])

  return ok(
    "/ip4/" & ipParts.join(".") & "/" & protocol & "/" & $port & "/p2p/" & peerIdBase58
  )
