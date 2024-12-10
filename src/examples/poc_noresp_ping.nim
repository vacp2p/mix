import chronicles, std/enumerate, chronos, std/sysrand
import ../mixnet_transport_adapter/[switch, transport]
import ../protocols/[noresp_ping]
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
  var noRespPingProto: seq[NoRespPing] = @[]
  var nodes: seq[Switch] = @[]
  for index, _ in enumerate(multiAddrs):
    let switch =
      createSwitch(libp2pPrivKeys[index], multiAddrs[index], index, numberOfNodes)
    if not switch.isNil:
      nodes.add(switch)
    else:
      warn "Failed to set up node", nodeIndex = index

    noRespPingProto.add(noresp_ping.NoRespPing.new(rng = rng))
    nodes[index].mount(noRespPingProto[index])
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
      break
  if transportIndex == -1:
    raise newException(ValueError, "Custom transport not found")

  let
    mixTransport = nodes[senderIndex].transports[transportIndex]
    peerId = nodes[receiverIndex].peerInfo.peerId
    peerIdOpt = Opt[PeerId].some(peerId)

  try:
    var conn = await MixnetTransportAdapter(mixTransport).dialWithProto(
      "", multiAddrs[receiverIndex], peerIdOpt, Opt.some(NoRespPingCodec)
    )

    let ping = await noRespPingProto[senderIndex].noRespPing(conn)
    info "Received ping: ", ping = ping
    await sleepAsync(1.seconds)
  except Exception as e:
    error "An error occurred during dialing: ", err = e.msg

  for index, node in enumerate(nodes):
    await node.stop()

  deleteNodeInfoFolder()
  deletePubInfoFolder()

when isMainModule:
  waitFor(mixnet_with_transport_adapter_poc())
