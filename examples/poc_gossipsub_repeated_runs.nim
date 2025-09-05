import chronicles, chronos, results
import std/[atomics, enumerate, sequtils, strformat, strutils, sugar]
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

type Node = tuple[switch: Switch, gossip: GossipSub, mix: MixProtocol, id: int]

proc createSwitch(libp2pPrivKey: SkPrivateKey, multiAddr: MultiAddress): Switch =
  result = SwitchBuilder
    .new()
    .withPrivateKey(PrivateKey(scheme: Secp256k1, skkey: libp2pPrivKey))
    .withAddress(multiAddr)
    .withRng(crypto.newRng())
    .withYamux()
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
      let switch = createSwitch(libp2pPrivKey, multiAddr)
      if not switch.isNil:
        nodes.add(switch)
      else:
        warn "Failed to set up node", nodeIndex = index

    return nodes

proc oneNode(node: Node, rcvdCnt: ptr Atomic[int]) {.async.} =
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
        discard rcvdCnt[].fetchAdd(1),
    )
  else:
    node.gossip.subscribe("message", nil)

  for msgNum in 0 ..< 5:
    await sleepAsync(500.milliseconds)
    let msg = fmt"Hello from Node {node.id}, Message No: {msgNum + 1}"
    discard await node.gossip.publish(
      "message",
      cast[seq[byte]](msg),
      publishParams = some(PublishParams(skipMCache: true, useCustomConn: true)),
    )

  await sleepAsync(1000.milliseconds)
  await node.switch.stop()

proc makeMixConnCb(mixProto: MixProtocol): CustomConnCreationProc =
  return proc(
      destAddr: Option[MultiAddress], destPeerId: PeerId, codec: string
  ): Connection {.gcsafe, raises: [].} =
    try:
      return mixProto.toConnection(destPeerId, codec).get()
    except CatchableError as e:
      error "Error during execution of MixEntryConnection callback: ", err = e.msg
      return nil

proc mixnet_gossipsub_test(): Future[int] {.async: (raises: [Exception]).} =
  let
    numberOfNodes = 5
    switch = setUpNodes(numberOfNodes)
  var nodes: seq[Node]
  var rcvdCnt: Atomic[int]
  rcvdCnt.store(0)

  for i in 0 ..< numberOfNodes:
    let mixProto = MixProtocol.new(i, numberOfNodes, switch[i]).valueOr:
      error "Mix protocol initialization failed", err = error
      return

    let mixConnCb = makeMixConnCb(mixProto)

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
          customConnCreationCB: mixConnCb, customPeerSelectionCB: mixPeerSelect
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
    allFuts.add(oneNode(node, addr rcvdCnt))

  await allFutures(allFuts)

  deleteNodeInfoFolder()
  deletePubInfoFolder()

  return rcvdCnt.load

import std/[tables, algorithm, math, strformat]

proc main() {.async: (raises: [Exception]).} =
  var results: seq[int] = @[]
  let n = 25

  # Run the test n times
  for i in 1 .. n:
    let rcvdCnt = await mixnet_gossipsub_test()
    results.add(rcvdCnt)

  # Display individual run results
  echo "\nSummary of all runs:"
  for i, count in results:
    echo fmt"Run {i+1}: {count} messages"

  # Calculate average
  let avgMessages = (results.sum().float / n.float).round(2)
  echo fmt"Average no. of messages received: {avgMessages:.2f}"

  # Calculate median
  results.sort() # Sort in place
  let median =
    if n mod 2 == 1:
      results[n div 2].float
    else:
      ((results[n div 2 - 1] + results[n div 2]).float / 2).round(2)
  echo fmt"Median no. of messages received: {median:.2f}"

  # Count occurrences of each message count
  var summary = initTable[int, int]()
  for count in results:
    summary.mgetOrPut(count, 0) += 1

  # Display frequency summary
  echo "\nSummary of message counts:"
  var summarySeq = collect(
    for k, v in summary:
      (k, v)
  )
  summarySeq.sort(
    proc(x, y: (int, int)): int =
      cmp(x[0], y[0])
  )
  for (numMessages, numRuns) in summarySeq:
    echo fmt"{numRuns} runs: {numMessages} messages"

when isMainModule:
  waitFor main()
