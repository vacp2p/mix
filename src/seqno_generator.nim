import crypto, times
import std/endians
import libp2p/peerid

type SeqNo* = object
  counter: uint32
  epoch: uint32 # Increments when counter wraps around

proc initSeqNo*(peerId: PeerId): SeqNo =
  var seqNo: SeqNo
  let peerIdHash = sha256_hash(peerId.data)
  for i in 0 .. 3:
    seqNo.counter = seqNo.counter or (uint32(peerIdHash[i]) shl (8 * (3 - i)))
  seqNo.epoch = 0 # Start with epoch 0
  return seqNo

proc generateSeqNo*(seqNo: var SeqNo, messageBytes: seq[byte]) =
  let
    currentTime = getTime().toUnix() * 1000
    currentTimeBytes = newSeq[byte](8)
  bigEndian64(addr currentTimeBytes[0], unsafeAddr currentTime)
  let messageHash = sha256_hash(messageBytes & currentTimeBytes)
  var cnt: uint32
  for i in 0 .. 3:
    cnt = cnt or (uint32(messageHash[i]) shl (8 * (3 - i)))
  seqNo.counter = (seqNo.counter + cnt) mod high(uint32)

proc incSeqNo*(seqNo: var SeqNo) =
  let oldCounter = seqNo.counter
  seqNo.counter = seqNo.counter + 1

  # Detect wraparound and increment epoch
  if seqNo.counter < oldCounter: # Overflow occurred
    seqNo.epoch = seqNo.epoch + 1

proc getSeqNo*(seqNo: SeqNo): uint32 =
  return seqNo.counter

proc getEpoch*(seqNo: SeqNo): uint32 =
  return seqNo.epoch

proc getFullSeqNo*(seqNo: SeqNo): (uint32, uint32) =
  ## Returns (counter, epoch) tuple for complete sequence identification
  return (seqNo.counter, seqNo.epoch)

proc compareSeqNo*(a, b: SeqNo): int =
  ## Compare two sequence numbers accounting for wraparound
  ## Returns: -1 if a < b, 0 if a == b, 1 if a > b
  if a.epoch != b.epoch:
    if a.epoch < b.epoch:
      return -1
    else:
      return 1

  # Same epoch, compare counters normally
  if a.counter < b.counter:
    return -1
  elif a.counter > b.counter:
    return 1
  else:
    return 0

proc isNextSeqNo*(current, next: SeqNo): bool =
  ## Check if 'next' is the immediate successor of 'current'
  if current.epoch == next.epoch:
    return next.counter == current.counter + 1
  elif next.epoch == current.epoch + 1:
    return current.counter == high(uint32) and next.counter == 0
  else:
    return false
