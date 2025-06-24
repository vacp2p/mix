import bearssl/rand, chronos, chronicles
import std/[options, sequtils, sets]
import libp2p/[multiaddress, protocols/pubsub/pubsubpeer, switch]
import ./[entry_connection, mix_protocol, protocol]

const D* = 4 # No. of peers to forward to

proc createMixEntryConnection*(
    srcMix: MixProtocol,
    destAddr: Option[MultiAddress],
    destPeerId: PeerId,
    codec: string,
): MixEntryConnection {.gcsafe, raises: [].} =
  var sendDialerFunc = proc(
      msg: seq[byte],
      proto: ProtocolType,
      destMultiAddr: Option[MultiAddress],
      destPeerId: PeerId,
  ): Future[void] {.async: (raises: [CancelledError, LPStreamError]).} =
    try:
      await srcMix.anonymizeLocalProtocolSend(msg, proto, destMultiAddr, destPeerId)
    except CatchableError as e:
      error "Error during execution of anonymizeLocalProtocolSend: ", err = e.msg
    return

  # Create and return a new MixEntryConnection
  MixEntryConnection.new(
    destAddr, destPeerId, ProtocolType.fromString(codec), sendDialerFunc
  )

proc mixPeerSelection*(
    allPeers: HashSet[PubSubPeer],
    directPeers: HashSet[PubSubPeer],
    meshPeers: HashSet[PubSubPeer],
    fanoutPeers: HashSet[PubSubPeer],
): HashSet[PubSubPeer] {.gcsafe, raises: [].} =
  var
    peers: HashSet[PubSubPeer]
    allPeersSeq = allPeers.toSeq()
  let rng = newRng()
  rng.shuffle(allPeersSeq)
  for p in allPeersSeq:
    peers.incl(p)
    if peers.len >= D:
      break
  return peers
