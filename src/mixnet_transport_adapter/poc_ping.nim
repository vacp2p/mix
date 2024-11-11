import std/enumerate, chronos, strutils
import ./[transport, upgrade]
import libp2p/[crypto/secp, multiaddress, builders, protocols/ping, transports/tcptransport]
import ../[mix_node]

proc setUpMixNet(numberOfNodes: int): (seq[string], seq[SkPrivateKey]) =
  # This is not actually GC-safe
  {.gcsafe.}:
    var multiAddrs: seq[string] = @[]
    var libp2pPrivKeys: seq[SkPrivateKey] = @[]

    initializeMixNodes(numberOfNodes)

    for index, node in enumerate(mixNodes):
      let nodeMixPubInfo = getMixPubInfoByIndex(index)
      let pubResult = writePubInfoToFile(nodeMixPubInfo, index)
      if pubResult == false:
        echo "Failed to write pub info to file for node ", $index

      let mixResult = writeMixNodeInfoToFile(node, index)
      if mixResult == false:
        echo "Failed to write mix node info to file for node ", $index

      let (multiAddr, _, _, _, libp2pPrivKey) = getMixNodeInfo(node)

      multiAddrs.add(multiAddr)
      libp2pPrivKeys.add(libp2pPrivKey)
      
    return (multiAddrs, libp2pPrivKeys)

proc mixnet_with_transport_adapter_poc() {.async.} =
  let
    numberOfNodes = 2
    nodeIndexA = 0
    nodeIndexB = 1

  let (multiAddrs, libp2pPrivKeys) = setUpMixNet(numberOfNodes)

  let
    inTimeout: Duration = 5.minutes
    outTimeout: Duration = 5.minutes
    transportFlags: set[ServerFlags] = {}

  let
    addressA = MultiAddress.init(multiAddrs[0].split("/mix/")[0]).value()
    addressB = MultiAddress.init(multiAddrs[1].split("/mix/")[0]).value()

    switchA = SwitchBuilder
      .new()
      .withPrivateKey(PrivateKey(scheme: Secp256k1, skkey: libp2pPrivKeys[0]))
      .withAddress(addressA)
      .withRng(crypto.newRng())
      .withMplex(inTimeout, outTimeout)
      .withTransport(
        proc(upgrade: Upgrade): Transport =
          let
            wrappedTransport = TcpTransport.new(transportFlags, upgrade)
            wrappedUpgrade = MixnetUpgradeAdapter.new(upgrade)
          MixnetTransportAdapter.new(wrappedTransport, wrappedUpgrade, nodeIndexA, numberOfNodes)
      )
      .withNoise()
      .build()

    switchB = SwitchBuilder
      .new()
      .withPrivateKey(PrivateKey(scheme: Secp256k1, skkey: libp2pPrivKeys[1]))
      .withAddress(addressB)
      .withRng(crypto.newRng())
      .withMplex(inTimeout, outTimeout)
      .withTransport(
        proc(upgrade: Upgrade): Transport =
          let
            wrappedTransport = TcpTransport.new(transportFlags, upgrade)
            wrappedUpgrade = MixnetUpgradeAdapter.new(upgrade)
          MixnetTransportAdapter.new(wrappedTransport, wrappedUpgrade, nodeIndexB, numberOfNodes)
      )
      .withNoise()
      .build()

  let
    rng = newRng()
    pingA = Ping.new(rng = rng)
    pingB = Ping.new(rng = rng)

  switchA.mount(pingA)
  switchB.mount(pingB)

  discard await allFinished(switchA.start(), switchB.start())

  echo "SwitchA listening on:"
  for addrs in switchA.peerInfo.addrs:
    echo addrs, " ", switchA.peerInfo.peerId, " ", addressA

  echo "SwitchB listening on:"
  for addrs in switchB.peerInfo.addrs:
    echo addrs, " ", switchB.peerInfo.peerId, " ", addressB

  var conn = await switchB.dial(switchA.peerInfo.peerId, @[addressA], PingCodec)
  echo "After switchB.dial - Connection type: ", conn.type

  discard await pingB.ping(conn)
  await sleepAsync(1.seconds)

when isMainModule:
  waitFor(mixnet_with_transport_adapter_poc())
