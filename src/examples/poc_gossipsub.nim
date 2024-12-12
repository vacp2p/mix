import chronicles, sequtils, std/enumerate, strutils, chronos, std/strformat, std/sysrand, stew/byteutils
import ../mixnet_transport_adapter/[protocol, transport]
import libp2p/[crypto/secp, multiaddress, builders, protocols/pubsub/gossipsub, transports/tcptransport]
import ../[mix_node]

proc createSwitch*(
    libp2pPrivKey: SkPrivateKey, multiAddr: MultiAddress, nodeIndex, numberOfNodes: int
): Switch =
  let
    inTimeout: Duration = 5.minutes
    outTimeout: Duration = 5.minutes
    transportFlags: set[ServerFlags] = {}

  let switch = SwitchBuilder
    .new()
    .withPrivateKey(PrivateKey(scheme: Secp256k1, skkey: libp2pPrivKey))
    .withAddress(multiAddr)
    .withRng(crypto.newRng())
    .withMplex(inTimeout, outTimeout)
    .withTransport(
      proc(upgrade: Upgrade): Transport =
        let
          wrappedTransport = TcpTransport.new(transportFlags, upgrade)
          mixnetAdapterResult = MixnetTransportAdapter.new(
            wrappedTransport, upgrade, nodeIndex, numberOfNodes
          )
        if mixnetAdapterResult.isOk:
          return mixnetAdapterResult.get
        else:
          error "Failed to create MixnetTransportAdapter",
            err = mixnetAdapterResult.error
          return wrappedTransport
    )
    .withTcpTransport()
    .withNoise()
    .build()

  if switch.isNil:
    error "Failed to create Switch", nodeIndex = nodeIndex
    return
  else:
    var sendFunc = proc(conn: Connection, proto: ProtocolType): Future[void] {.async.} =
      try:
        await callHandler(switch, conn, proto)
      except CatchableError as e:
        error "Error during execution of sendThroughMixnet: ", err = e.msg
        # TODO: handle error
      return
    for index, transport in enumerate(switch.transports):
      if transport of MixnetTransportAdapter:
        MixnetTransportAdapter(transport).setCallBack(sendFunc)
        break
    return switch

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
      let parts = (multiAddrStr).split("/mix/")
      if parts.len != 2:
        error "Invalid multiaddress format", parts = parts
        return
      let tcpAddr = MultiAddress.init(parts[0]).valueOr:
        error "Failed to initialize MultiAddress", err = error
        return
      multiAddrs.add(tcpAddr)
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
      switch.mount(gossip)
      nodes.add((switch, gossip))
      await switch.start()
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