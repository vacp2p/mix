import chronicles, sequtils, strutils, chronos, results
import std/[enumerate, strformat]
import ../mix
import libp2p
import
  libp2p/[
    crypto/secp,
    protocols/pubsub/gossipsub,
    protocols/pubsub/pubsubpeer,
    protocols/pubsub/rpc/messages,
  ]
import ./poc_gossipsub_utils

proc createSwitch(
    libp2pPrivKey: Opt[SkPrivateKey] = Opt.none(SkPrivateKey),
    multiAddr: Opt[MultiAddress] = Opt.none(MultiAddress),
): Switch =
  let rng = crypto.newRng()
  var b = SwitchBuilder.new().withRng(rng).withYamux().withTcpTransport().withNoise()

  if libp2pPrivKey.isSome:
    b = b.withPrivateKey(PrivateKey(scheme: Secp256k1, skkey: libp2pPrivKey.get()))
  else:
    let keyPair = SkKeyPair.random(rng[])
    let libp2pPrivKey = keyPair.seckey
    b = b.withPrivateKey(PrivateKey(scheme: Secp256k1, skkey: libp2pPrivKey))

  if multiAddr.isSome:
    b = b.withAddress(multiAddr.get())
  else:
    let multiAddr = MultiAddress.init("/ip4/0.0.0.0/tcp/0").valueOr:
      error "Failed to initialize MultiAddress", err = error
      return
    b = b.withAddress(multiAddr)

  return b.build()

proc makeMixConnCb(mixProto: MixProtocol): CustomConnCreationProc =
  return proc(
      destAddr: Option[MultiAddress], destPeerId: PeerId, codec: string
  ): Connection {.gcsafe, raises: [].} =
    try:
      if destAddr.isNone:
        error "NO DEST ADD AVAILABLE"
        return

      let d = Destination.forwardToAddr(destPeerId, destAddr.get())
      return mixProto.toConnection(d, codec).get()
    except CatchableError as e:
      error "Error during execution of MixEntryConnection callback: ", err = e.msg
      return nil

proc createGossip(switch: Switch, mixProto: Opt[MixProtocol]): GossipSub =
  var customConnCallbacks: Option[CustomConnectionCallbacks] =
    if mixProto.isSome:
      let mixConnCb = makeMixConnCb(mixProto.get())
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
      some(
        CustomConnectionCallbacks(
          customConnCreationCB: mixConnCb, customPeerSelectionCB: mixPeerSelect
        )
      )
    else:
      none(CustomConnectionCallbacks)

  let gossip = GossipSub.init(
    switch = switch, triggerSelf = true, customConnCallbacks = customConnCallbacks
  )
  switch.mount(gossip)
  return gossip

proc connectNodesTCP(switchA: Switch, switchB: Switch) {.async.} =
  await switchA.connect(
    switchB.peerInfo.peerId, switchB.peerInfo.addrs.filterIt(TCP.match(it))
  )

proc setUpNodes(numNodes: int): seq[Switch] =
  # Initialize mix nodes
  let mixNodes = initializeMixNodes(numNodes).valueOr:
    error "Could not initialize mixnodes", err = error
    return

  var nodes: seq[Switch] = @[]

  for index, node in enumerate(mixNodes):
    # Write public info of all mix nodes
    let nodePubInfo = mixNodes.getMixPubInfoByIndex(index).valueOr:
      error "Get mix pub info by index error", err = error
      continue

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
    let switch = createSwitch(Opt.some(libp2pPrivKey), Opt.some(multiAddr))
    nodes.add(switch)

  return nodes

proc mixnet_gossipsub_test() {.async: (raises: [Exception]).} =
  # Nodes A =  Gossip and Mix
  # Nodes B and C = Gossip
  # A -> C,  B -> C
  # Nodes D E F G =  Mix nodes 
  # A, D, E, F, G = Mesh

  var
    numMixNodes = 5
    numGossipNodes = 3
    switch = setUpNodes(numMixNodes)

  let
    switchA = switch[0]
    switchD = switch[1]
    switchE = switch[2]
    switchF = switch[3]
    switchG = switch[4]
    switchB = createSwitch()
    switchC = createSwitch()

  var nodes: seq[MixProtocol]

  for i in 0 ..< numMixNodes:
    let mixProto = MixProtocol.new(i, numMixNodes, switch[i]).valueOr:
      error "Mix protocol initialization failed", err = error
      return

    switch[i].mount(mixProto)
    nodes.add(mixProto)

  let
    mixprotoA = nodes[0]
    mixprotoD = nodes[1]
    mixprotoE = nodes[2]
    mixprotoF = nodes[3]
    mixprotoG = nodes[4]

  let
    gossipA = createGossip(switchA, Opt.some(mixprotoA))
    gossipB = createGossip(switchB, Opt.none(MixProtocol))
    gossipC = createGossip(switchC, Opt.none(MixProtocol))

  await allFutures(
    switchA.start(),
    switchB.start(),
    switchC.start(),
    switchD.start(),
    switchD.start(),
    switchE.start(),
    switchF.start(),
    switchG.start(),
  )

  # Gossip network
  await connectNodesTCP(switchA, switchC)
  await connectNodesTCP(switchB, switchC)

  # Mixnet
  let mixnet = @[switchA, switchD, switchE, switchF, switchG]
  for i in 0 ..< mixnet.len:
    for j in i + 1 ..< mixnet.len:
      await connectNodesTCP(mixnet[i], mixnet[j])

  gossipA.subscribe(
    "message",
    proc(topic: string, data: seq[byte]) {.async.} =
      info "Message received at A", msg = cast[string](data)
    ,
  )
  gossipB.subscribe(
    "message",
    proc(topic: string, data: seq[byte]) {.async.} =
      info "Message received at B", msg = cast[string](data)
    ,
  )
  gossipC.subscribe(
    "message",
    proc(topic: string, data: seq[byte]) {.async.} =
      info "Message received at C", msg = cast[string](data)
    ,
  )

  await sleepAsync(2.seconds)

  echo "===================="
  echo "===================="
  echo "===================="
  echo "===================="
  echo "===================="
  echo "===================="
  echo "===================="
  echo "===================="
  echo "===================="
  echo "===================="
  echo "===================="
  echo "===================="
  echo "===================="

  # message published by A will reach C and B,  (arriving to C via mix)
  discard await gossipA.publish(
    "message",
    cast[seq[byte]]("Hello World from A"),
    publishParams = some(PublishParams(skipMCache: true, useCustomConn: true)),
  )

  echo "===================="
  echo "===================="
  echo "===================="

  await sleepAsync(5.seconds)

  discard await gossipB.publish("message", cast[seq[byte]]("Hello World from B"))

  await sleepAsync(10.seconds)

  #and B will publish a message normally.
  #and message published by B will reach to all the other nodes, and C will not use the exit node from prev message  as peer 

  deleteNodeInfoFolder()
  deletePubInfoFolder()

when isMainModule:
  waitFor(mixnet_gossipsub_test())
