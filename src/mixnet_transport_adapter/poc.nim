import std/enumerate, chronos
import ./[transport, upgrade]
import ../[mix_protocol, mix_node]
import libp2p/[multiaddress, builders, transports/tcptransport]

proc setUpMixNet(numberOfNodes: int) =
  # This is not actually GC-safe
  {.gcsafe.}:
    initializeMixNodes(numberOfNodes)

    for index, node in enumerate(mixNodes):
      let nodeMixPubInfo = getMixPubInfoByIndex(index)
      let pubResult = writePubInfoToFile(nodeMixPubInfo, index)
      if pubResult == false:
        echo "Failed to write pub info to file for node ", $index

      let mixResult = writeMixNodeInfoToFile(node, index)
      if mixResult == false:
        echo "Failed to write mix node info to file for node ", $index

proc mixnet_with_transport_adapter_poc() {.async.} =
  let
    numberOfNodes = 2
    nodeIndexA = 0
    nodeIndexB = 1

  setUpMixNet(numberOfNodes)

  let
    inTimeout: Duration = 5.minutes
    outTimeout: Duration = 5.minutes
    transportFlags: set[ServerFlags] = {}

  let
    addressA = MultiAddress.init("/ip4/127.0.0.3/tcp/8081").value()
    addressB = MultiAddress.init("/ip4/127.0.0.4/tcp/8082").value()

    switchA = SwitchBuilder
      .new()
      .withAddress(addressA)
      .withRng(crypto.newRng())
      .withMplex(inTimeout, outTimeout)
      .withTransport(
        proc(upgrade: Upgrade): Transport =
          let
            wrappedTransport = TcpTransport.new(transportFlags, upgrade)
            wrappedUpgrade = MixnetUpgradeAdapter.new(upgrade)
          MixnetTransportAdapter.new(wrappedTransport, wrappedUpgrade)
      )
      .withNoise()
      .build()

    switchB = SwitchBuilder
      .new()
      .withAddress(addressB)
      .withRng(crypto.newRng())
      .withMplex(inTimeout, outTimeout)
      .withTransport(
        proc(upgrade: Upgrade): Transport =
          let
            wrappedTransport = TcpTransport.new(transportFlags, upgrade)
            wrappedUpgrade = MixnetUpgradeAdapter.new(upgrade)
          MixnetTransportAdapter.new(wrappedTransport, wrappedUpgrade)
      )
      .withNoise()
      .build()

  let
    mixA = MixProtocol.new(nodeIndexA, numberOfNodes, switchA)
    mixB = MixProtocol.new(nodeIndexB, numberOfNodes, switchB)

  switchA.mount(mixA)
  switchB.mount(mixB)

  let switchFut = await allFinished(switchA.start(), switchB.start())

  var conn = await switchB.dial(switchA.peerInfo.peerId, @[addressA], @[MixProtocolID])

  let msg = newSeq[byte](2413)
  await conn.writeLp(msg)
  await sleepAsync(1.seconds)

when isMainModule:
  waitFor(mixnet_with_transport_adapter_poc())
