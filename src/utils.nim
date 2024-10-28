import config
import strutils
import stew/base58

const addrBytesSize* = 46

proc bytesToUInt16*(data: openArray[byte]): uint16 =
    assert len(data) == 2, "Data must be exactly 2 bytes long to convert to uint16"
    result = uint16(data[0]) shl 8 or uint16(data[1])

proc uint16ToBytes*(value: uint16): seq[byte] =
    result = @[
      byte(value shr 8),
      byte(value and 0xFF)
    ]

proc bytesToUInt32*(data: openArray[byte]): uint32 =
    assert len(data) == 4, "Data must be exactly 4 bytes long to convert to uint32"
    result = uint32(data[0]) shl 24 or
             uint32(data[1]) shl 16 or
             uint32(data[2]) shl 8 or
             uint32(data[3])

proc uint32ToBytes*(value: uint32): seq[byte] =
    result = @[
      byte(value shr 24),
      byte(value shr 16 and 0xFF),
      byte(value shr 8 and 0xFF),
      byte(value and 0xFF)
    ]

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
    result.add(uint16ToBytes(uint16(port)))

    # PeerID (39 bytes)
    let peerIdBase58 = parts[6]
    assert peerIdBase58.len == 53, "Peer ID must be exactly 53 characters"
    let peerIdBytes = Base58.decode(peerIdBase58)
    assert peerIdBytes.len == 39, "Peer ID must be exactly 39 bytes"
    result.add(peerIdBytes)

    assert result.len == addrSize, "Address must be exactly " & $addrSize & " bytes"

    return result

proc bytesToMultiAddr*(bytes: openArray[byte]): string =
    assert bytes.len == addrSize, "Address must be exactly " & $addrSize & " bytes"

    var ipParts: seq[string] = @[]
    for i in 0..3:
        ipParts.add($bytes[i]) # ToDo: Add support for ipv6. Supporting ipv4 only for testing purposes

    let protocol = if bytes[4] == 0: "tcp" else: "quic" # ToDo: TLS or QUIC (Using TCP for testing purposes)

    let port = bytesToUInt16(bytes[5..6])

    let peerIdBase58 = Base58.encode(bytes[7..^1])

    return "/ip4/" & ipParts.join(".") & "/" & protocol & "/" & $port &
            "/p2p/" & peerIdBase58
