import chronicles, chronos, results, strutils
import std/[enumerate, sysrand]
import libp2p
import libp2p/[crypto/secp]
import ./protocols/noresp_ping

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

proc mixnetSimulation() {.async: (raises: [Exception]).} =
  let
    numberOfNodes = 10
    nodes = setUpNodes(numberOfNodes)

  var
    mixProto: seq[MixProtocol] = @[]
    noRespPingProto: seq[NoRespPing] = @[]

  # Start nodes
  let rng = newRng()
  for index, _ in enumerate(nodes):
    noRespPingProto.add(noresp_ping.NoRespPing.new(rng = rng))

    let proto = MixProtocol.new(index, numberOfNodes, nodes[index]).valueOr:
      error "Mix protocol initialization failed", err = error
      return # We'll fwd requests, so let's register how should the exit node behave

    mixProto.add(proto)

    nodes[index].mount(noRespPingProto[index])
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
    MixDestination.init(
      nodes[receiverIndex].peerInfo.peerId, nodes[receiverIndex].peerInfo.addrs[0]
    ),
    NoRespPingCodec,
  ).valueOr:
    error "could not obtain connection", err = error
    return

  discard await noRespPingProto[senderIndex].noRespPing(conn)
  await sleepAsync(1.seconds)

  deleteNodeInfoFolder()
  deletePubInfoFolder()

when isMainModule:
  waitFor(mixnetSimulation())
