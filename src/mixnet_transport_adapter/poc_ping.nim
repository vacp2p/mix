import sequtils, std/enumerate, chronos, options, std/sysrand, strutils
import ./[logical_connection, transport, protocol]
import
  libp2p/[crypto/secp, multiaddress, builders, protocols/ping, transports/tcptransport]
import ../[mix_node]

proc cryptoRandomInt(max: int): Result[int, string] =
  if max == 0:
    return err("Max cannot be zero.")
  var bytes: array[8, byte]
  discard urandom(bytes)
  let value = cast[uint64](bytes)
  return ok(int(value mod uint64(max)))

proc createSwitch(
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
        let wrappedTransport = TcpTransport.new(transportFlags, upgrade)
        MixnetTransportAdapter.new(wrappedTransport, upgrade, nodeIndex, numberOfNodes)
    )
    .withNoise()
    .build()

  if switch.isNil:
    error "Failed to create Switch", nodeIndex = nodeIndex
    return
  else:
    var sendFunc = proc(conn: Connection, proto: ProtocolType): Future[void] {.async.} =
      try:
        await switch.callHandler(conn, proto)
      except CatchableError as e:
        echo "Error during execution of sendThroughMixnet: ", e.msg
        # TODO: handle error
      return
    for index, transport in enumerate(switch.transports):
      if transport of MixnetTransportAdapter:
        MixnetTransportAdapter(transport).setCallBack(sendFunc)
        break
    return switch

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

proc mixnet_with_transport_adapter_poc() {.async.} =
  let
    numberOfNodes = 10
    (libp2pPrivKeys, multiAddrs) = setUpNodes(numberOfNodes)

  # Start nodes
  let rng = newRng()
  var pingProto: seq[Ping] = @[]
  var nodes: seq[Switch] = @[]
  for index, _ in enumerate(multiAddrs):
    let switch =
      createSwitch(libp2pPrivKeys[index], multiAddrs[index], index, numberOfNodes)
    if not switch.isNil:
      nodes.add(switch)
    else:
      warn "Failed to set up node", nodeIndex = index

    pingProto.add(Ping.new(rng = rng))
    nodes[index].mount(pingProto[index])
    await nodes[index].start()
  await sleepAsync(1.seconds)

  let cryptoRandomIntResult = cryptoRandomInt(numberOfNodes)
  if cryptoRandomIntResult.isErr:
    error "Failed to generate random number", err = cryptoRandomIntResult.error
    return
  let senderIndex = cryptoRandomIntResult.value
  var receiverIndex = 0
  if senderIndex < numberOfNodes - 1:
    receiverIndex = senderIndex + 1

  let transports = nodes[senderIndex].transports
  var transportIndex = -1
  for index, transport in enumerate(transports):
    if transport of MixnetTransportAdapter:
      transportIndex = index
  if transportIndex == -1:
    raise newException(ValueError, "Custom transport not found")

  let
    mixTransport = nodes[senderIndex].transports[transportIndex]
    peerId = nodes[receiverIndex].peerInfo.peerId
    peerIdOpt = Opt[PeerId](oResultPrivate: true, vResultPrivate: peerId)

  try:
    var conn = await MixnetTransportAdapter(mixTransport).dialWithProto(
      "", multiAddrs[receiverIndex], peerIdOpt, Opt.some(PingCodec)
    )

    discard await pingProto[senderIndex].ping(conn)
    await sleepAsync(1.seconds)
  except Exception as e:
    echo "An error occurred during dialing: ", e.msg

  #[var conn = await nodes[senderIndex].dial(nodes[receiverIndex].peerInfo.peerId, @[multiAddrs[receiverIndex]], PingCodec)
  echo "After dial connection type: ", conn.type

  discard await pingProto[senderIndex].ping(conn)
  await sleepAsync(1.seconds)]#

  for index, node in enumerate(nodes):
    await node.stop()

  deleteNodeInfoFolder()
  deletePubInfoFolder()

when isMainModule:
  waitFor(mixnet_with_transport_adapter_poc())
