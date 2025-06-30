import std/endians, times
import libp2p/peerid
import ./crypto

type SeqNo* = object
  counter: uint32

proc initSeqNo*(peerId: PeerId): SeqNo {.raises: [].} =
  var seqNo: SeqNo
  let peerIdHash = sha256_hash(peerId.data)
  for i in 0 .. 3:
    seqNo.counter = seqNo.counter or (uint32(peerIdHash[i]) shl (8 * (3 - i)))
  return seqNo

proc generateSeqNo*(seqNo: var SeqNo, messageBytes: seq[byte]) {.raises: [].} =
  let
    currentTime = getTime().toUnix() * 1000
    currentTimeBytes = newSeq[byte](8)
  bigEndian64(addr currentTimeBytes[0], unsafeAddr currentTime)
  let messageHash = sha256_hash(messageBytes & currentTimeBytes)
  var cnt: uint32
  for i in 0 .. 3:
    cnt = cnt or (uint32(messageHash[i]) shl (8 * (3 - i)))
  seqNo.counter = (seqNo.counter + cnt) mod high(uint32)

proc incSeqNo*(seqNo: var SeqNo) {.raises: [].} =
  seqNo.counter = (seqNo.counter + 1) mod high(uint32)
    # ToDo: Manage sequence no. overflow in a way that it does not affect re-assembly

proc getSeqNo*(seqNo: SeqNo): uint32 {.raises: [].} =
  return seqNo.counter
