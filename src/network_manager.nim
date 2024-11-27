import chronos
import libp2p
import libp2p/multiaddress
import libp2p/peerinfo
import libp2p/crypto/crypto
import strutils
import options

type NetworkManager* = ref object
  switch*: Switch

proc newNetworkManager*(): NetworkManager =
  let rng = newRng()
  let seckey = PrivateKey.random(ECDSA, rng[]).tryGet()
  result = NetworkManager(
    switch: newStandardSwitch(
      privKey = some(seckey),
      addrs = @[MultiAddress.init("/ip4/127.0.0.1/tcp/0").tryGet()],
      secureManagers = [SecureProtocol.Noise],
      rng = rng,
    )
  )

proc start*(nm: NetworkManager) {.async.} =
  await nm.switch.start()

proc stop*(nm: NetworkManager) {.async.} =
  await nm.switch.stop()

proc dialPeer*(
    nm: NetworkManager, peerMultiaddr: string, protocolId: string
): Future[Connection] {.async.} =
  let ma = MultiAddress.init(peerMultiaddr).tryGet()
  let parts = peerMultiaddr.split("/")
  let peerIdStr = parts[^1]
  let peerId = PeerID.init(peerIdStr).tryGet()

  echo "Attempting to dial peer: ", peerIdStr
  echo "Using protocol: ", protocolId

  try:
    let conn = await nm.switch.dial(peerId, @[ma], protocolId)
    echo "Connection established successfully"
    return conn
  except CatchableError as e:
    echo "Error during dial: ", e.msg
    raise e

proc getPeerInfo*(nm: NetworkManager): PeerInfo =
  nm.switch.peerInfo

proc mount*(nm: NetworkManager, proto: LPProtocol) =
  nm.switch.mount(proto)
