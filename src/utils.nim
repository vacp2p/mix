import config
import strutils
import stew/base58

const addrBytesSize* = 46

proc multiAddrToBytes*(multiAddr: string): seq[byte] =
  var parts = multiAddr.split('/')
  result = @[]

  # IP address (4 bytes) ToDo: Add support for ipv6. Supporting ipv4 only for testing purposes
  let ipParts = parts[2].split('.')
  for part in ipParts:
    result.add(byte(parseInt(part)))

  # Protocol (1 byte) ToDo: TLS or QUIC
  assert parts[3] == "tcp" or parts[3] == "quic", "Unsupported protocol"
  if parts[3] == "tcp": # Using TCP for testing purposes
    result.add(byte(0))
  elif parts[3] == "quic":
    result.add(byte(1))

  # Port (2 bytes)
  let port = parseInt(parts[4])
  result.add(byte((port shr 8) and 0xFF))
  result.add(byte(port and 0xFF))

  # PeerID (39 bytes)
  let peerIdBase58 = parts[6]
  assert peerIdBase58.len == 53, "Peer ID must be exactly 53 characters"
  let peerIdBytes = Base58.decode(peerIdBase58)
  assert peerIdBytes.len == 39, "Peer ID must be exactly 39 bytes"
  result.add(peerIdBytes)

  assert result.len == addrSize,"Address must be exactly " & $addrSize & " bytes"

  return result

proc bytesToMultiAddr*(bytes: openArray[byte]): string =
  assert bytes.len == addrSize, "Address must be exactly " & $addrSize & " bytes"
  
  var ipParts: seq[string] = @[]
  for i in 0..3:
    ipParts.add($bytes[i]) # ToDo: Add support for ipv6. Supporting ipv4 only for testing purposes

  let protocol = if bytes[4] == 0: "tcp" else: "quic" # ToDo: TLS or QUIC (Using TCP for testing purposes)
  
  let port = (int(bytes[5]) shl 8) or int(bytes[6])
  
  let peerIdBase58 = Base58.encode(bytes[7..^1])

  return "/ip4/" & ipParts.join(".") & "/" & protocol & "/" & $port & "/p2p/" & peerIdBase58