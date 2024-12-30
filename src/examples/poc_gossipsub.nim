import chronicles, sequtils, std/enumerate, strutils, chronos
import std/[strformat, sysrand]
import ../mixnet_transport_adapter/[protocol, transport]
import
  libp2p/[
    crypto/secp,
    multiaddress,
    builders,
    protocols/pubsub/gossipsub,
    protocols/pubsub/rpc/messages,
    transports/tcptransport,
  ]
import ../[mix_node]

type Node = tuple[switch: Switch, gossip: GossipSub, id: int]

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
    .withTcpTransport()
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
      return
    for index, transport in enumerate(switch.transports):
      if transport of MixnetTransportAdapter:
        MixnetTransportAdapter(transport).setCallBack(sendFunc)
        break
    return switch

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

proc oneNode(node: Node, rng: ref HmacDrbgContext) {.async.} =
  node.gossip.addValidator(
    ["message"],
    proc(topic: string, message: Message): Future[ValidationResult] {.async.} =
      return ValidationResult.Accept,
  )

  if node.id == 0:
    node.gossip.subscribe(
      "message",
      proc(topic: string, data: seq[byte]) {.async.} =
        echo fmt"Node {node.id} received: {cast[string](data)}"
      ,
    )
  else:
    node.gossip.subscribe("message", nil)

  for msgNum in 0 ..< 5:
    await sleepAsync(500.milliseconds)
    let msg = fmt"Hello from Node {node.id}, Message No: {msgNum + 1}"

    discard await node.gossip.publish("message", cast[seq[byte]](msg))

  await sleepAsync(1000.milliseconds)
  await node.switch.stop()

proc mixnet_gossipsub_test() {.async.} =
  let
    numberOfNodes = 5
    (libp2pPrivKeys, multiAddrs) = setUpNodes(numberOfNodes)
  var nodes: seq[Node]

  for i in 0 ..< numberOfNodes:
    let switch = createSwitch(libp2pPrivKeys[i], multiAddrs[i], i, numberOfNodes)
    if not switch.isNil:
      let gossip = GossipSub.init(switch = switch, triggerSelf = true)
      switch.mount(gossip)
      await switch.start()
      nodes.add((switch, gossip, i))
    else:
      warn "Failed to set up node", nodeIndex = i

  await connectNodesTCP(nodes)

  var allFuts: seq[Future[void]]
  for node in nodes:
    allFuts.add(oneNode(node, newRng()))

  await allFutures(allFuts)

  deleteNodeInfoFolder()
  deletePubInfoFolder()

when isMainModule:
  waitFor(mixnet_gossipsub_test())
