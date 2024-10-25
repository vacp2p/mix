import std/[enumerate], unittest2, libp2p
import libp2p/protocols/ping

import ../src/[mix_protocol, mix_node], utils/[async]

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

suite "Mix Protocol Test":
  TODO: Fix the tests
  The tests listed here are not working as expected for now
  They serve as a reference for information flow and basic debugging

  asyncTest "Mix to Mix":
    # Given a number of nodes
    let
      numberOfNodes = 2
      nodeIndexA = 0
      nodeIndexB = 1

    # And their mix node info is initialized
    setUpMixNet(numberOfNodes)

    # And two mix protocols
    let
      switchA = newStandardSwitch()
      switchB = newStandardSwitch()
      mixA = MixProtocol.new(nodeIndexA, numberOfNodes, switchA)
      mixB = MixProtocol.new(nodeIndexB, numberOfNodes, switchB)

    # And mix protocols also handle `OtherProtocol`
    # Note: This is for demonstration purposes only, to show how you need to specify what protocols does the MixProtocol handle
    # An alternative is to use a matcher when mounting. E.g.:
    # ```
    # let matcher: Matcher = proc(proto: string): bool {.gcsafe, raises: [].} =
    #   return @[].contains(proto)
    #
    # switchA.mount(mixA, matcher)
    # switchB.mount(mixB, matcher)
    # ```
    # This is probably not the proper way to do it. For now let's consider it a demonstration.
    let otherProtocol = "OtherProtocol"
    mixA.codecs.add(otherProtocol)
    mixB.codecs.add(otherProtocol)

    # And are mounted on their respective switches
    switchA.mount(mixA)
    switchB.mount(mixB)

    # And the switches are started
    let switchFut = await allFinished(switchA.start(), switchB.start())

    # And the switches are connected to each other
    await switchA.connect(switchB.peerInfo.peerId, switchB.peerInfo.addrs)

    # When an `OtherProtocol` connection is established between the two mix nodes
    var conn = await switchB.dial(
      switchA.peerInfo.peerId, switchA.peerInfo.addrs, "OtherProtocol"
    )

    # And a message is sent from one node to the other
    # This message is not a valid MixProtocol message, but for demonstration purposes to test the connection
    let msg = newSeq[byte](2413)
    await conn.writeLp(msg)

    # To do proper checking here, either we need a callback in the receiver MixProtocol
    # Or add a receiver protocol that allows us to read the message
    await sleepAsync(1000)

  asyncTest "From PingA to MixA to MixB to PingB":
    # This is a WIP test currently being used to understand how to make local connections between protocols

    # Given a number of nodes
    let
      numberOfNodes = 2
      nodeIndexA = 0
      nodeIndexB = 1

    # And their mix node info is initialized
    setUpMixNet(numberOfNodes)

    # And two mix protocols
    let
      switchA = newStandardSwitch()
      switchB = newStandardSwitch()
      mixA = MixProtocol.new(nodeIndexA, numberOfNodes, switchA)
      mixB = MixProtocol.new(nodeIndexB, numberOfNodes, switchB)
      pingA = Ping.new()
      pingB = Ping.new()

    # And mix protocols also handle `PingCodec`
    # mixA.codecs.add(PingCodec)
    # mixB.codecs.add(PingCodec)

    # And are mounted on their respective switches
    switchA.mount(mixA)
    # switchB.mount(mixB)
    switchA.mount(pingA)
    # switchB.mount(pingB)

    # And the switches are started
    # let switchFut = await allFinished(switchA.start(), switchB.start())
    let switchFut = await allFinished(switchA.start())

    # And the switches are connected to each other
    # await switchA.connect(switchB.peerInfo.peerId, switchB.peerInfo.addrs)

    # When a `PingCodec` connection is established between the two mix nodes
    # var conn =
    #   await switchB.dial(switchA.peerInfo.peerId, switchA.peerInfo.addrs, PingCodec)
    var conn = await switchA.dialer.dial(switchA.peerInfo.peerId, @[MixProtocolID])

    # And a message is sent from one node to the other
    # if switchA.peerInfo.protocols.contains(MixProtocolID):
    #   let futString = switchA.ms.handle(conn)
    # else:
    #   echo "Switch A does not have MixProtocolID"

    # let peers = switchA.peers.peers
    # for peer in peers:
    #   let protos = peer.protocols.mapIt(it.codec)
    #   if "/protocol1/1.0.0" in protos:
    #     let stream = await p.switch.dial(peer.peerId, "/protocol1/1.0.0")
    #     await stream.writeLp("Message from Protocol2")
    #     await stream.close()

    # And a message is sent from one node to the other
    # echo "# Test Connection: ", conn.shortLog()
    # let response = await pingB.ping(conn)
    # let response = await pingA.ping(conn)
    # echo "# Ping response: ", response
    # await conn.close()
    # Entra so por un handler
