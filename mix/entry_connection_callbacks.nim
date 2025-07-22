# TODO: this file should likely become mix.nim in the root of the project

import chronos, chronicles, results
import std/[sequtils, sets]
import libp2p/[multiaddress, protocols/pubsub/pubsubpeer, switch]
import ./[entry_connection, mix_protocol]

const D* = 4 # No. of peers to forward to

proc toConnection*(
    srcMix: MixProtocol,
    destPeerId: PeerId,
    destForwardToAddr: Opt[MultiAddress],
    codec: string,
): Connection {.gcsafe, raises: [].} =
  MixEntryConnection.new(srcMix, destPeerId, destForwardToAddr, codec)

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
