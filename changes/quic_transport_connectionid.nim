# File: quic/transport/connectionid.nim
# Changes:
# - Remove the distinct type from `ConnectionId`. It caused some operations not to behave as expected. E.g.: The "destructor"
# - Comment out the overridden procs. Given `distinct` is removed, the default implementation is used.

import std/strutils
import std/hashes
import pkg/nimcrypto

type ConnectionId* = seq[byte]

const DefaultConnectionIdLength* = 16

# proc `==`*(x: ConnectionId, y: ConnectionId): bool {.borrow.}
# proc `len`*(x: ConnectionId): int {.borrow.}
# proc `hash`*(x: ConnectionId): Hash {.borrow.}

proc `$`*(id: ConnectionId): string =
  "0x" & cast[string](id).toHex

proc randomConnectionId*(len = DefaultConnectionIdLength): ConnectionId =
  var bytes = newSeq[byte](len)
  doAssert len == randomBytes(addr bytes[0], len)
  ConnectionId(bytes)
