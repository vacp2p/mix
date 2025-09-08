import chronos, chronicles, results
import metrics, metrics/chronos_httpserver
import stew/[byteutils, endians2]
import ../poc_gossipsub_utils
import std/[strformat, random, posix, hashes, math, sequtils, strutils, tables, os, nativesockets]
import ../../mix
import ./node
import
  libp2p,
  libp2p/[
    crypto/secp,
    multiaddress,
    builders,
    protocols/pubsub/gossipsub,
    protocols/pubsub/pubsubpeer,
    protocols/pubsub/rpc/messages,
  ]

proc createSwitch(id, port: int, isMix: bool, filePath: string): Switch =
  {.gcsafe.}:
    var
      multiAddrStr: string
      libp2pPubKey: SkPublicKey
      libp2pPrivKey: SkPrivateKey

    var mixNodes: MixNodes = @[]

    if isMix:
      mixNodes = initializeMixNodes(1, port).valueOr:
        error "Could not generate mix nodes"
        return

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

    let addresses = getInterfaces().filterIt(it.name == "eth0").mapIt(it.addresses)
    if addresses.len < 1 or addresses[0].len < 1:
      error "Can't find local ip!"
      return

    let
      externalAddr = ($addresses[0][0].host).split(":")[0]
      peerId = switch.peerInfo.peerId
      externalMultiAddr = fmt"/ip4/{externalAddr}/tcp/{port}/p2p/{peerId}"

    if isMix:
      let initRes = mixNodes.initMixMultiAddrByIndex(0, externalMultiAddr)
      if initRes.isErr:
        error "Failed to initialize mix node", id = 0, err = initRes.error
        return
      let writeNodeRes =
        writeMixNodeInfoToFile(mixNodes[0], id, filePath / fmt"nodeInfo")
      if writeNodeRes.isErr:
        error "Failed to write mix info to file", nodeId = id, err = writeNodeRes.error
        return

      let nodePubInfo = mixNodes.getMixPubInfoByIndex(0).valueOr:
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
  info "Starting metrics HTTP server", serverIp = $serverIp, serverPort = $serverPort

  let metricsServerRes = MetricsHttpServerRef.new($serverIp, serverPort)
  if metricsServerRes.isErr():
    return err("metrics HTTP server start failed: " & $metricsServerRes.error)

  let server = metricsServerRes.value
  try:
    waitFor server.start()
  except CatchableError:
    return err("metrics HTTP server start failed: " & getCurrentExceptionMsg())

  info "Metrics HTTP server started", serverIp = $serverIp, serverPort = $serverPort
  ok(metricsServerRes.value)

const uidLen = 32

proc makeMixConnCb(mixProto: MixProtocol): CustomConnCreationProc =
  return proc(
      destAddr: Option[MultiAddress], destPeerId: PeerId, codec: string
  ): Connection {.gcsafe, raises: [].} =
    try:
      return mixProto.toConnection(destPeerId, codec).get()
    except CatchableError as e:
      error "Error during execution of MixEntryConnection callback: ", err = e.msg
      return nil

proc main() {.async.} =
  randomize()

  let
    hostname = getHostname()
    node_count = parseInt(getEnv("NODES"))
    messages = parseInt(getEnv("MESSAGES"))
    msg_rate = parseInt(getEnv("MSGRATE"))
    msg_size = parseInt(getEnv("MSGSIZE"))
    publisherCount = parseInt(getEnv("PUBLISHERS"))
    mixCount = publisherCount # Publishers will be the mix nodes for now
    connectTo = parseInt(getEnv("CONNECTTO"))
    filePath = getEnv("FILEPATH", "./")
    rng = libp2p.newRng()

  if publisherCount > node_count:
    error "Publisher count is greater than total node count"
    return

  info "Hostname", host = hostname
  let myId = getHostname().split('-')[^1].parseInt()
  info "ID", id = myId

  let
    isPublisher = myId < publisherCount
      # [0..<publisherCount] contains all the publishers
    isMix = isPublisher # Publishers will be the mix nodes for now
    myport = parseInt(getEnv("PORT", "5000"))
    switch = createSwitch(myId, myport, isMix, filePath)

  await sleepAsync(10.seconds)

  var gossipSub: GossipSub

  if isMix:
    let mixProto = MixProtocol.new(myId, mixCount, switch, filePath).expect(
        "could not instantiate mix"
      )

    let mixConn = makeMixConnCb(mixProto)

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
  info "Starting metrics HTTP server"
  let metricsServer = startMetricsServer(parseIpAddress("0.0.0.0"), Port(8008))
  gossipSub.parameters.floodPublish = true
  gossipSub.parameters.opportunisticGraftThreshold = -10000
  gossipSub.parameters.heartbeatInterval = 10.seconds
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
      msgId = uint64.fromBytesLE(data[8 ..< 16])
      sentTime = Moment.init(int64(timestampNs), Nanosecond)
      recvTime = Moment.now()
      delay = recvTime - sentTime

    info "Received message",
      msgId = msgId, sentAt = timestampNs, delayMs = delay.milliseconds()

  proc messageValidator(
      topic: string, msg: Message
  ): Future[ValidationResult] {.async.} =
    return ValidationResult.Accept

  gossipSub.subscribe("test", messageHandler)
  gossipSub.addValidator(["test"], messageValidator)
  switch.mount(gossipSub)
  await switch.start()

  info "PeerId ", peerid = switch.peerInfo.peerId
  info "Listening", addrs = switch.peerInfo.addrs

  info "Waiting 20 seconds for node building..."

  await sleepAsync(20.seconds)

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
  var index = 0
  while true:
    if connected >= connectTo:
      break
    while true:
      try:
        info "Trying to connect", addrs = addrs[index]
        let peerId =
          await switch.connect(addrs[index], allowUnknownPeerId = true).wait(5.seconds)
        connected.inc()
        index.inc()
        info "Connected!"
        break
      except CatchableError as exc:
        error "Failed to dial", err = exc.msg
        info "Waiting 15 seconds..."
        await sleepAsync(15.seconds)

  await sleepAsync(2.seconds)

  info "Mesh size", meshSize = gossipSub.mesh.getOrDefault("test").len

  info "Publishing turn", id = myId
  for msg in 0 ..< messages: #client.param(int, "message_count"):
    await sleepAsync(msg_rate)
    if msg mod publisherCount == myId:
      let timestampNs = Moment.now().epochNanoSeconds()
      let msgId = uint64(msg)

      var payload: seq[byte]
      payload.add(toBytesLE(timestampNs.uint64))
      payload.add(toBytesLE(msgId))
      payload.add(newSeq[byte](msg_size - 16)) # Fill the rest with padding

      info "Publishing message", msgId = msgId, timestamp = timestampNs

      doAssert(
        (
          await gossipSub.publish(
            "test",
            payload,
            publishParams = some(PublishParams(skipMCache: true, useCustomConn: true)),
          )
        ) > 0
      )
  await sleepAsync(999999999)

waitFor(main())
