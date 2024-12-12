import chronicles, sequtils, std/enumerate, strutils, chronos, std/strformat, std/sysrand, stew/byteutils
import ../mixnet_transport_adapter/[switch, transport]
import libp2p/[crypto/secp, multiaddress, builders, protocols/pubsub/gossipsub, transports/tcptransport]
import ../[mix_node]

proc connectNodesTCP(nodes: seq[tuple[switch: Switch, gossip: GossipSub]]) {.async.} =
  for i in 0 ..< nodes.len:
    for j in max(0, i-2) .. min(nodes.len-1, i+2):
      if i != j:
        let tcpAddr = nodes[j].switch.peerInfo.addrs.filterIt(TCP.match(it))
        if tcpAddr.len > 0:
          try:
            await nodes[i].switch.connect(nodes[j].switch.peerInfo.peerId, tcpAddr)
          except CatchableError as e:
            warn "Failed to connect nodes", src = i, dst = j, error = e.msg

proc setUpNodes(numberOfNodes: int): (seq[SkPrivateKey], seq[MultiAddress]) =
  # This is not actually GC-safe
  {.gcsafe.}:
    initializeMixNodes(numberOfNodes)

    var libp2pPrivKeys: seq[SkPrivateKey] = @[]
    var multiAddrs: seq[MultiAddress] = @[]

    for index, node in enumerate(mixNodes):
      let nodeMixPubInfo = getMixPubInfoByIndex(index)
      let pubResult = writePubInfoToFile(nodeMixPubInfo, index)
      if pubResult == false:
        error "Failed to write pub info to file", nodeIndex = index
        continue

      let mixResult = writeMixNodeInfoToFile(node, index)
      if mixResult == false:
        error "Failed to write mix node info to file", nodeIndex = index
        continue

      let (multiAddrStr, _, _, _, libp2pPrivKey) = getMixNodeInfo(node)
      multiAddrs.add(MultiAddress.init(multiAddrStr).value())
      libp2pPrivKeys.add(libp2pPrivKey)

    return (libp2pPrivKeys, multiAddrs)

proc mixnet_gossipsub_test() {.async.} =
  let
    numberOfNodes = 10
    (libp2pPrivKeys, multiAddrs) = setUpNodes(numberOfNodes)
  var nodes: seq[tuple[switch: Switch, gossip: GossipSub]]
  
  for i in 0 ..< numberOfNodes:
    let switch = createSwitch(libp2pPrivKeys[i], multiAddrs[i], i, numberOfNodes)
    if not switch.isNil:
      let
        gossip = GossipSub.init(switch = switch, triggerSelf = true)
        transportFlags: set[ServerFlags] = {}
        upgrade = Upgrade.new()
        tcpTransport = TcpTransport.new(transportFlags, upgrade)
      switch.mount(gossip)
      switch.addTransport(tcpTransport)
      let parts = ($multiAddrs[i]).split("/mix/")
      if parts.len != 2:
        error "Invalid multiaddress format", parts = parts
        return
      let tcpAddr = MultiAddress.init(parts[0]).valueOr:
        error "Failed to initialize MultiAddress", err = error
        return
      nodes.add((switch, gossip))
      await switch.start()
      switch.peerInfo.addrs.add(tcpAddr)
    else:
      warn "Failed to set up node", nodeIndex = i

  await sleepAsync(1.seconds)

  await connectNodesTCP(nodes)

  for i, node in nodes:
    node.gossip.subscribe("chat", proc(topic: string, data: seq[byte]) {.async.} = 
      echo fmt"Node {i} received: {cast[string](data)}")

  await sleepAsync(2.seconds)

  for i, node in nodes:
    discard await node.gossip.publish("chat", fmt"Hello from Node {i}".toBytes())

  await sleepAsync(2.seconds)

  for node in nodes:
    await node.switch.stop()

  deleteNodeInfoFolder()
  deletePubInfoFolder()

when isMainModule:
  waitFor(mixnet_gossipsub_test())