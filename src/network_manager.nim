import chronos
import libp2p
import libp2p/multiaddress
import libp2p/peerinfo
import strutils

type 
  NetworkManager* = ref object
    switch*: Switch

proc newNetworkManager*(): NetworkManager =
  let rng = newRng()
  result = NetworkManager(
    switch: newStandardSwitch(rng = rng)
  )

proc start*(nm: NetworkManager) {.async.} =
  await nm.switch.start()

proc stop*(nm: NetworkManager) {.async.} =
  await nm.switch.stop()

proc dialNextHop*(nm: NetworkManager, nextHopMultiaddr: string, protocolId: string): Future[Connection] =
  let ma = MultiAddress.init(nextHopMultiaddr).tryGet()
  let parts = nextHopMultiaddr.split("/")
  let peerIdStr = parts[^1]
  let peerId = PeerID.init(peerIdStr).tryGet()
  nm.switch.dial(peerId, @[ma], protocolId)

proc mount*(nm: NetworkManager, proto: LPProtocol) =
  nm.switch.mount(proto)

proc getPeerInfo*(nm: NetworkManager): PeerInfo =
  nm.switch.peerInfo