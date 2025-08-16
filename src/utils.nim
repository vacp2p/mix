import results, strutils, net, tables
import stew/base58
import config

const addrBytesSize* = 46 # Legacy constant for backward compatibility

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

proc parseIPv4ToBytes(ipStr: string): Result[seq[byte], string] =
  let ipParts = ipStr.split('.')
  if ipParts.len != 4:
    return err("Invalid IPv4 address format")

  var ipBytes: seq[byte] = @[byte(4)] # IP version
  for part in ipParts:
    try:
      let ipPart = parseInt(part)
      if ipPart < 0 or ipPart > 255:
        return err("Invalid IPv4 address format")
      ipBytes.add(byte(ipPart))
    except ValueError:
      return err("Invalid IPv4 address format")
  ok(ipBytes)

proc parseIPv6ToBytes(ipStr: string): Result[seq[byte], string] =
  try:
    let ipv6Addr = parseIpAddress(ipStr)
    if ipv6Addr.family != IpAddressFamily.IPv6:
      return err("Invalid IPv6 address")

    var ipBytes: seq[byte] = @[byte(6)] # IP version
    for i in 0 .. 15:
      ipBytes.add(ipv6Addr.address_v6[i])
    ok(ipBytes)
  except ValueError:
    err("Invalid IPv6 address format")

proc multiAddrToBytes*(multiAddr: string): Result[seq[byte], string] =
  let parts = multiAddr.split('/')
  if parts.len != 7:
    return err("Invalid multiaddress format")

  # Protocol handler map
  let ipParsers = {"ip4": parseIPv4ToBytes, "ip6": parseIPv6ToBytes}.toTable()

  # Parse IP address using appropriate handler
  let parser = ipParsers.getOrDefault(parts[1])
  if parser.isNil:
    return err("Unsupported IP version, only ip4 and ip6 are supported")

  let ipBytesRes = parser(parts[2])
  if ipBytesRes.isErr:
    return ipBytesRes

  var res = ipBytesRes.get()

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

  # Check for correct size based on IP version
  let expectedSize = if res[0] == 4: ipv4AddrSize else: ipv6AddrSize
  if res.len != expectedSize:
    return err("Address must be exactly " & $expectedSize & " bytes")

  return ok(res)

proc bytesIPv4ToString(bytes: openArray[byte], offset: int): string =
  var ipParts: seq[string] = @[]
  for i in offset .. offset + 3:
    ipParts.add($bytes[i])
  "/ip4/" & ipParts.join(".")

proc bytesIPv6ToString(bytes: openArray[byte], offset: int): string =
  var ipv6Bytes: array[16, byte]
  for i in 0 .. 15:
    ipv6Bytes[i] = bytes[offset + i]

  var ipv6Addr: IpAddress
  ipv6Addr.family = IpAddressFamily.IPv6
  ipv6Addr.address_v6 = ipv6Bytes
  "/ip6/" & $ipv6Addr

type IPHandler =
  tuple[
    bytesToString: proc(bytes: openArray[byte], offset: int): string {.nimcall.},
    protocolOffset: int,
    expectedSize: int,
  ]

proc bytesToMultiAddr*(bytes: openArray[byte]): Result[string, string] =
  if bytes.len < 1:
    return err("Address must be at least 1 byte for version")

  let ipVersion = bytes[0]

  # Define handlers for each IP version
  let handlers = {
    4'u8:
      (bytesToString: bytesIPv4ToString, protocolOffset: 5, expectedSize: ipv4AddrSize),
    6'u8:
      (bytesToString: bytesIPv6ToString, protocolOffset: 17, expectedSize: ipv6AddrSize),
  }.toTable()

  let handler = handlers.getOrDefault(ipVersion)
  if handler.bytesToString.isNil:
    return err("Unsupported IP version: " & $ipVersion)

  if bytes.len != handler.expectedSize:
    return err(
      "Address must be exactly " & $handler.expectedSize & " bytes for IPv" & $ipVersion
    )

  # Parse IP address
  let ipStr = handler.bytesToString(bytes, 1) # Skip version byte

  # Parse protocol
  let protocol = if bytes[handler.protocolOffset] == 0: "tcp" else: "quic"

  # Parse port
  let portRes =
    bytesToUInt16(bytes[handler.protocolOffset + 1 .. handler.protocolOffset + 2])
  if portRes.isErr:
    return err(portRes.error)

  # Parse peer ID
  let peerIdBase58 = Base58.encode(bytes[handler.protocolOffset + 3 ..^ 1])

  ok(ipStr & "/" & protocol & "/" & $portRes.get() & "/p2p/" & peerIdBase58)
