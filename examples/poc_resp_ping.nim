import chronicles, chronos, results, strutils
import std/[enumerate, sysrand]
import libp2p
import libp2p/[crypto/secp, protocols/ping]
import ../mix

proc cryptoRandomInt(max: int): Result[int, string] =
  if max == 0:
    return err("Max cannot be zero.")
  var bytes: array[8, byte]
  discard urandom(bytes)
  let value = cast[uint64](bytes)
  return ok(int(value mod uint64(max)))

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

# Set up nodes
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

proc mixnetSimulation() {.async: (raises: [Exception]).} =
  let
    numberOfNodes = 10
    nodes = setUpNodes(numberOfNodes)

  var
    mixProto: seq[MixProtocol] = @[]
    pingProto: seq[Ping] = @[]

  # Start nodes
  for index, _ in enumerate(nodes):
    pingProto.add(Ping.new())

    let proto = MixProtocol.new(index, numberOfNodes, nodes[index]).valueOr:
      error "Mix protocol initialization failed", err = error
      return

    # We'll fwd requests, so let's register how should the exit node behave
    proto.registerFwdBehavior(
      PingCodec,
      proc(
          conn: Connection, msg: seq[byte]
      ): Future[seq[byte]] {.async: (raises: [CancelledError, LPStreamError]).} =
        debug "writing ping to destination"
        await conn.write(msg)
        debug "reading ping from destination"
        let resultBuf = newSeqUninit[byte](32)
        await conn.readExactly(addr resultBuf[0], 32)
        return resultBuf,
    )

    mixProto.add(proto)

    nodes[index].mount(pingProto[index])
    nodes[index].mount(mixProto[index])

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

  let conn = mixProto[senderIndex].toConnection(
    Destination.forwardToAddr(
      nodes[receiverIndex].peerInfo.peerId, nodes[receiverIndex].peerInfo.addrs[0]
    ),
    PingCodec,
    Opt.some(MixParameters(expectReply: Opt.some(true), numSurbs: Opt.some(byte(1)))),
  ).valueOr:
    error "Could not obtain connection", err = error
    return

  let response = await pingProto[senderIndex].ping(conn)

  await sleepAsync(1.seconds)

  deleteNodeInfoFolder()
  deletePubInfoFolder()

when isMainModule:
  waitFor(mixnetSimulation())
