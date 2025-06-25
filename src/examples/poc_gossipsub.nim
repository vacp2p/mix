import chronicles, sequtils, strutils, chronos
import std/[enumerate, options, strformat, sysrand]
import
  ../[entry_connection, entry_connection_callbacks, mix_node, mix_protocol, protocol]
import
  libp2p/[
    crypto/secp,
    multiaddress,
    builders,
    protocols/pubsub/gossipsub,
    protocols/pubsub/pubsubpeer,
    protocols/pubsub/rpc/messages,
    transports/tcptransport,
  ]

type Node = tuple[switch: Switch, gossip: GossipSub, mix: MixProtocol, id: int]

proc createSwitch(libp2pPrivKey: SkPrivateKey, multiAddr: MultiAddress): Switch =
  let
    inTimeout: Duration = 5.minutes
    outTimeout: Duration = 5.minutes
  result = SwitchBuilder
    .new()
    .withPrivateKey(PrivateKey(scheme: Secp256k1, skkey: libp2pPrivKey))
    .withAddress(multiAddr)
    .withRng(crypto.newRng())
    .withMplex(inTimeout, outTimeout)
    .withTcpTransport()
    .withNoise()
    .build()

proc connectNodesTCP(nodes: seq[Node]) {.async.} =
  for index, node in nodes:
    for otherNodeIdx in index - 1 .. index + 2:
      if otherNodeIdx notin 0 ..< nodes.len or otherNodeIdx == index:
        continue
      let
        otherNode = nodes[otherNodeIdx]
        tcpAddr = otherNode.switch.peerInfo.addrs.filterIt(TCP.match(it))

      if tcpAddr.len > 0:
        try:
          await node.switch.connect(otherNode.switch.peerInfo.peerId, tcpAddr)
        except CatchableError as e:
          warn "Failed to connect nodes", src = index, dst = otherNodeIdx, error = e.msg

proc setUpNodes(numNodes: int): seq[Switch] =
  # This is not actually GC-safe
  {.gcsafe.}:
    # Initialize mix nodes
    discard initializeMixNodes(numNodes)

    var nodes: seq[Switch] = @[]

    for index, node in enumerate(mixNodes):
      # Write public info of all mix nodes
      let nodePubInfoRes = getMixPubInfoByIndex(index)
      if nodePubInfoRes.isErr:
        error "Get mix pub info by index error", err = nodePubInfoRes.error
        continue
      let nodePubInfo = nodePubInfoRes.get()

      let writePubRes = writeMixPubInfoToFile(nodePubInfo, index)
      if writePubRes.isErr:
        error "Failed to write pub info to file", nodeIndex = index
        continue

      # Write info of all mix nodes
      let writeNodeRes = writeMixNodeInfoToFile(node, index)
      if writeNodeRes.isErr:
        error "Failed to write mix info to file", nodeIndex = index
        continue

      # Extract private key and multiaddress
      let (multiAddrStr, _, _, _, libp2pPrivKey) = getMixNodeInfo(node)

      let multiAddr = MultiAddress.init(multiAddrStr.split("/p2p/")[0]).valueOr:
        error "Failed to initialize MultiAddress", err = error
        return

      # Create switch
      let switch = createSwitch(libp2pPrivKey, multiAddr)
      if not switch.isNil:
        nodes.add(switch)
      else:
        warn "Failed to set up node", nodeIndex = index

    return nodes

proc oneNode(node: Node) {.async.} =
  node.gossip.addValidator(
    ["message"],
    proc(topic: string, message: Message): Future[ValidationResult] {.async.} =
      return ValidationResult.Accept,
  )

  if node.id == 0:
    node.gossip.subscribe(
      "message",
      proc(topic: string, data: seq[byte]) {.async.} =
        info "Message received", nodeId = node.id, msg = cast[string](data)
      ,
    )
  else:
    node.gossip.subscribe("message", nil)

  for msgNum in 0 ..< 5:
    await sleepAsync(500.milliseconds)
    let msg = fmt"Hello from Node {node.id}, Message No: {msgNum + 1}"
    discard
      await node.gossip.publish("message", cast[seq[byte]](msg), useCustomConn = true)

  await sleepAsync(1000.milliseconds)
  await node.switch.stop()

proc mixnet_gossipsub_test() {.async.} =
  let
    numberOfNodes = 5
    switch = setUpNodes(numberOfNodes)
  var nodes: seq[Node]

  for i in 0 ..< numberOfNodes:
    let mixProto = MixProtocol.new(i, numberOfNodes, switch[i]).valueOr:
      error "Mix protocol initialization failed", err = error
      return

    let mixConn = proc(
        destAddr: Option[MultiAddress], destPeerId: PeerId, codec: string
    ): Connection {.gcsafe, raises: [].} =
      try:
        return mixProto.createMixEntryConnection(destAddr, destPeerId, codec)
      except CatchableError as e:
        error "Error during execution of MixEntryConnection callback: ", err = e.msg
        return nil

    let mixPeerSelect = proc(
        allPeers: HashSet[PubSubPeer],
        directPeers: HashSet[PubSubPeer],
        meshPeers: HashSet[PubSubPeer],
        fanoutPeers: HashSet[PubSubPeer],
    ): HashSet[PubSubPeer] {.gcsafe, raises: [].} =
      try:
        return mixPeerSelection(allPeers, directPeers, meshPeers, fanoutPeers)
      except CatchableError as e:
        error "Error during execution of MixPeerSelection callback: ", err = e.msg
        return initHashSet[PubSubPeer]()

    let gossip = GossipSub.init(
      switch = switch[i],
      triggerSelf = true,
      customConnCallbacks = some(
        CustomConnectionCallbacks(
          customConnCreationCB: mixConn, customPeerSelectionCB: mixPeerSelect
        )
      ),
    )
    switch[i].mount(gossip)
    switch[i].mount(mixProto)
    await switch[i].start()
    nodes.add((switch[i], gossip, mixProto, i))

  await connectNodesTCP(nodes)

  var allFuts: seq[Future[void]]
  for node in nodes:
    allFuts.add(oneNode(node))

  await allFutures(allFuts)

  deleteNodeInfoFolder()
  deletePubInfoFolder()

when isMainModule:
  waitFor(mixnet_gossipsub_test())
