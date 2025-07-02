#[
in nu shell run as so (requires alacritty):
rm -rf infos log-*; ^bash -c 'for i in {0..4}; do alacritty -e bash -c "./main $i 5 20 50 1 4 | tee >(grep INF > log-$i.txt) | grep INF; echo Done. Press enter to close...; read" & done
^rm previos files                      ^5 nodes     ^make a terminal    ^run                    ^ output info logs to file     ^display info in terminal
]#
import chronos, chronicles, hashes, math, strutils, tables
import metrics, metrics/chronos_httpserver
import stew/[byteutils, endians2]
import
  std/[
    options, strformat, os, random,
    posix, 
  ]
import node
import
  mix/[
    entry_connection_callbacks, mix_node, mix_protocol, 
  ]
import
  libp2p,
  libp2p/[
    crypto/secp,
    multiaddress,
    builders,
    protocols/pubsub/gossipsub,
    protocols/pubsub/pubsubpeer,
    protocols/pubsub/rpc/messages,
    transports/tcptransport,
  ]
from times import getTime, toUnix, fromUnix, `-`, initTime, `$`, inMilliseconds
from nativesockets import getHostname

proc createSwitch(id, port: int, isMix: bool, filePath: string): Switch =
  {.gcsafe.}:
    var
      multiAddrStr: string
      libp2pPubKey: SkPublicKey
      libp2pPrivKey: SkPrivateKey

    if isMix:
      discard initializeMixNodes(1, port)

      let mixNodeInfo = getMixNodeInfo(mixNodes[0])
      multiAddrStr = mixNodeInfo[0]
      libp2pPubKey = mixNodeInfo[3]
      libp2pPrivKey = mixNodeInfo[4]
    else:
      discard initializeNodes(1, port)

      (multiAddrStr, libp2pPubKey, libp2pPrivKey) = getNodeInfo(nodes[0])

    let multiAddrParts = multiAddrStr.split("/p2p/")
    let multiAddr = MultiAddress.init(multiAddrParts[0]).valueOr:
      error "Failed to initialize MultiAddress", err = error
      return

    let switch = SwitchBuilder
      .new()
      .withPrivateKey(PrivateKey(scheme: Secp256k1, skkey: libp2pPrivKey))
      .withAddress(multiAddr)
      .withRng(crypto.newRng())
      .withYamux()
      .withTcpTransport()
      .withNoise()
      .build()

    if switch.isNil:
      warn "Failed to set up node", nodeId = id
      return

    let
      peerId = switch.peerInfo.peerId
      externalMultiAddr = fmt"/ip4/127.0.0.1/tcp/{port}/p2p/{peerId}"

    if isMix:
      discard initMixMultiAddrByIndex(0, externalMultiAddr)
      let writeNodeRes =
        writeMixNodeInfoToFile(mixNodes[0], id, filePath / fmt"nodeInfo")
      if writeNodeRes.isErr:
        error "Failed to write mix info to file", nodeId = id, err = writeNodeRes.error
        return

      let nodePubInfo = getMixPubInfoByIndex(0).valueOr:
        error "Get mix pub info by index error", err = error
        return

      let writeMixPubInfoRes =
        writeMixPubInfoToFile(nodePubInfo, id, filePath / fmt"pubInfo")
      if writeMixPubInfoRes.isErr:
        error "Failed to write mix pub info to file", nodeId = id
        return

    let pubInfo = initPubInfo(externalMultiAddr, libp2pPubKey)

    let writePubInfoRes = writePubInfoToFile(pubInfo, id, filePath / fmt"libp2pPubInfo")
    if writePubInfoRes.isErr:
      error "Failed to write pub info to file", nodeId = id
      return

    return switch

proc msgIdProvider(m: Message): Result[MessageId, ValidationResult] =
  return ok(($m.data.hash).toBytes())

proc startMetricsServer(
    serverIp: IpAddress, serverPort: Port
): Result[MetricsHttpServerRef, string] =
  # info "Starting metrics HTTP server", serverIp = $serverIp, serverPort = $serverPort

  let metricsServerRes = MetricsHttpServerRef.new($serverIp, serverPort)
  if metricsServerRes.isErr():
    return err("metrics HTTP server start failed: " & $metricsServerRes.error)

  let server = metricsServerRes.value
  try:
    waitFor server.start()
  except CatchableError:
    return err("metrics HTTP server start failed: " & getCurrentExceptionMsg())

  # info "Metrics HTTP server started", serverIp = $serverIp, serverPort = $serverPort
  ok(metricsServerRes.value)

proc main() {.async.} =
  let args = commandLineParams()
  echo "args: {id} {count} {rate} {size} {pub_count} {conn to}"
  randomize()

  let 
    myId = parseInt(args[0])
  #   hostname = fmt "node-{myId}"
  # info "Hostname", host = hostname
    # -e NODES="$N" \
    # -e MSGRATE=10 \
    # -e MSGSIZE=20 \
    # -e PUBLISHERS=5 \
    # -e CONNECTTO=4 \
    # -e LOG_LEVEL=TRACE \
  let
    node_count = parseInt(args[1]) # parseInt(getEnv("NODES"))
    msg_rate = parseInt(args[2]) # parseInt(getEnv("MSGRATE"))
    msg_size = parseInt(args[3]) # parseInt(getEnv("MSGSIZE"))
    publisherCount = 1 # parseInt(getEnv("PUBLISHERS"))
    mixCount = node_count # publisherCount # Publishers will be the mix nodes for now
    connectTo = parseInt(args[5]) # parseInt(getEnv("CONNECTTO"))
    filePath = "./infos"
    rng = libp2p.newRng()

  if publisherCount > node_count:
    error "Publisher count is greater than total node count"
    return


  let
    isPublisher = myId < mixCount
      # [0..<publisherCount] contains all the publishers
    isMix = myId < mixCount
    myport = 50000 + myId
    switch = createSwitch(myId, myport, isMix, filePath)


  await sleepAsync(1.seconds)

  var gossipSub: GossipSub

  if isMix:
    let mixProto = MixProtocol.new(myId, mixCount, switch, filePath).expect(
        "could not instantiate mix"
      )

    let mixConn = proc(
        destAddr: Option[MultiAddress], destPeerId: PeerId, codec: string
    ): Connection {.gcsafe, raises: [].} =
      try:
        return mixProto.createMixEntryConnection(none(MultiAddress), none(PeerId), codec)
      except CatchableError as e:
        error "Error during execution of MixEntryConnection callback", err = e.msg
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
        error "Error during execution of MixPeerSelection callback", err = e.msg
        return initHashSet[PubSubPeer]()

    gossipSub = GossipSub.init(
      switch = switch,
      triggerSelf = true,
      msgIdProvider = msgIdProvider,
      verifySignature = false,
      anonymize = true,
      customConnCallbacks = some(
        CustomConnectionCallbacks(
          customConnCreationCB: mixConn, customPeerSelectionCB: mixPeerSelect
        )
      ),
    )

    switch.mount(mixProto)
  else:
    gossipSub = GossipSub.init(
      switch = switch,
      triggerSelf = true,
      msgIdProvider = msgIdProvider,
      verifySignature = false,
      anonymize = true,
    )

  # Metrics
  # info "Starting metrics HTTP server"
  let metricsServer = startMetricsServer(parseIpAddress("0.0.0.0"), Port(8008))

  gossipSub.parameters.floodPublish = true
  gossipSub.parameters.opportunisticGraftThreshold = -10000
  gossipSub.parameters.heartbeatInterval = 1.seconds
  gossipSub.parameters.pruneBackoff = 60.seconds
  gossipSub.parameters.gossipFactor = 0.25
  gossipSub.parameters.d = 6
  gossipSub.parameters.dLow = 4
  gossipSub.parameters.dHigh = 8
  gossipSub.parameters.dScore = 6
  gossipSub.parameters.dOut = 6 div 2
  gossipSub.parameters.dLazy = 6
  gossipSub.topicParams["test"] = TopicParams(
    topicWeight: 1,
    firstMessageDeliveriesWeight: 1,
    firstMessageDeliveriesCap: 30,
    firstMessageDeliveriesDecay: 0.9,
  )

  proc messageHandler(topic: string, data: seq[byte]) {.async.} =
    if data.len < 16:
      warn "Message too short"
      return

    let
      timestampNs = uint64.fromBytesLE(data[0 ..< 8])
      secs: int64 = cast[int64](timestampNs).div(1_000_000_000)
      nanos = times.NanosecondRange(cast[int64](timestampNs).mod(1_000_000_000))
      time = times.initTime(secs, nanos)
      msgId = uint64.fromBytesLE(data[8 ..< 16])

    info "Handler",
      nw = times.format(getTime(), "mm:ss.ffffff"), tm=times.format(time, "mm:ss.ffffff")

  proc messageValidator(
      topic: string, msg: Message
  ): Future[ValidationResult] {.async.} =
    return ValidationResult.Accept

  gossipSub.subscribe("test", messageHandler)
  gossipSub.addValidator(["test"], messageValidator)
  switch.mount(gossipSub)
  await switch.start()

  # info "Listening", addrs = switch.peerInfo.addrs

  let sleeptime = 1
  info "Waiting for: ", time = sleeptime

  await sleepAsync(sleeptime.seconds)

  var connected = 0
  var addrs: seq[MultiAddress]

  for i in 0 ..< node_count:
    if i == myId:
      continue

    let pubInfo = readPubInfoFromFile(i, filePath / fmt"libp2pPubInfo").expect(
        "should be able to read pubinfo"
      )
    let (multiAddr, _) = getPubInfo(pubInfo)
    let ma = MultiAddress.init(multiAddr).expect("should be a multiaddr")
    addrs.add ma

  rng.shuffle(addrs)
  var conn_count = 0
  var index = 0
  while true:
    if connected >= connectTo:
      break
    while true:
      try:
        # info "Trying to connect", addrs = addrs[index]
        let peerId =
          await switch.connect(addrs[index], allowUnknownPeerId = true).wait(20.seconds)
        connected.inc()
        index.inc()
        conn_count += 1
        break
      except CatchableError as exc:
        error "Failed to dial", err = exc.msg
        info "Waiting 15 seconds..."
        await sleepAsync(6.seconds)
  doAssert(conn_count == connectTo)

  await sleepAsync(1.seconds)

  # info "Mesh size", meshSize = gossipSub.mesh.getOrDefault("test").len

  # info "Publishing turn", id = myId

  let count = 2
  for msg in 3 ..< 4: #client.param(int, "message_count"):
    if msg mod publisherCount == myId:
      # info "Sending message", time = times.getTime()
      let now = getTime()
      let timestampNs = now.toUnix().int64 * 1_000_000_000 + times.nanosecond(now).int64
      let msgId = uint64(msg)

      var payload: seq[byte]
      payload.add(newSeq[byte](msg_size - 16)) # Fill the rest with padding

      info "Publishing", msgId = msgId, timestamp = timestampNs

      let pub_res = await gossipSub.publish("test", payload, useCustomConn = true)
      if pub_res <= 0:
        error "publish fail", res = pub_res
        doAssert(pub_res > 0)
      await sleepAsync(msg_rate.milliseconds())
  await sleepAsync(5.seconds())
  info "Done", node=myId

waitFor(main())
