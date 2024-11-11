import chronicles, chronos, options, tables
import libp2p/[multiaddress, stream/connection, transports/transport, upgrademngrs/upgrade]
import ./[connection, muxer]
import ../[mix_node, tag_manager]

type MixnetTransportAdapter* = ref object of Transport
  mixNodeInfo: MixNodeInfo
  pubNodeInfo: Table[PeerId, MixPubInfo]
  transport: Transport
  tagManager: TagManager

proc loadMixNodeInfo*(index: int): MixNodeInfo {.raises: [].} =
  let mixNodeInfoOpt = readMixNodeInfoFromFile(index)
  assert mixNodeInfoOpt.isSome, "Failed to load node info from file."
  return mixNodeInfoOpt.get()

proc loadAllButIndexMixPubInfo*(index, numNodes: int): Table[PeerId, MixPubInfo] {.raises: [].} =
  var pubInfoTable = initTable[PeerId, MixPubInfo]()
  for i in 0 ..< numNodes:
    if i != index:
      let pubInfoOpt = readMixPubInfoFromFile(i)
      if pubInfoOpt.isSome:
        let pubInfo = pubInfoOpt.get()
        let (multiAddr, _, _) = getMixPubInfo(pubInfo)
        let peerId = getPeerIdFromMultiAddr(multiAddr)
        pubInfoTable[peerId] = pubInfo
  return pubInfoTable

method log*(self: MixnetTransportAdapter): string {.gcsafe.} =
  "<MixnetTransportAdapter>"

proc handlesStart(address: MultiAddress): bool {.gcsafe.} =
  return TcpMix.match(address)

method start*(self: MixnetTransportAdapter, addrs: seq[MultiAddress]) {.async.} =
  echo "# Start"
  for i, ma in addrs:
    if not handlesStart(ma):
      warn "Invalid address detected, skipping!", address = ma
      continue

  if len(addrs) != 0:
    await procCall Transport(self).start(addrs)
    await self.transport.start(addrs)
  else:
    raise (ref transport.TransportError)(msg: "Mix transport couldn't start, no supported addr was provided.")

method stop*(self: MixnetTransportAdapter) {.async.} =
  echo "# Stop"
  await self.transport.stop()
  await procCall self.Transport.stop()

proc acceptWithMixnet(self: MixnetTransportAdapter): Future[Connection] {.async.} =
  echo "> MixnetTransportAdapter::accept"
  let connection = await self.transport.accept()
  echo "< MixnetTransportAdapter::accept"
  MixnetConnectionAdapter.new(connection)

method accept*(self: MixnetTransportAdapter): Future[Connection] {.gcsafe.} =
  echo "# Accept"
  # self.transport.accept()
  self.acceptWithMixnet()

method dialWithMixnet*(
    self: MixnetTransportAdapter,
    hostname: string,
    address: MultiAddress,
    peerId: Opt[PeerId] = Opt.none(PeerId),
): Future[Connection] {.base, async.} =
  echo "> MixnetTransportAdapter::dialWithMixnet1 - ", $peerId
  let connection = await self.transport.dial(hostname, address, peerId)
  echo "Connection: ", connection.shortLog()
  let x = MixnetConnectionAdapter.new(connection)
  echo "MixnetConnectionAdapter: ", x.shortLog()
  x
  # connection

method dial*(
    self: MixnetTransportAdapter,
    hostname: string,
    address: MultiAddress,
    peerId: Opt[PeerId] = Opt.none(PeerId),
): Future[Connection] {.gcsafe.} =
  echo "> MixnetTransportAdapter::dial1"
  self.dialWithMixnet(hostname, address, peerId)

method dialWithMixnet*(
    self: MixnetTransportAdapter,
    address: MultiAddress,
    peerId: Opt[PeerId] = Opt.none(PeerId),
): Future[Connection] {.base, async.} =
  echo "MixnetTransportAdapter::dialWithMixnet2"
  let connection = await self.transport.dial(address, peerId)
  MixnetConnectionAdapter.new(connection)

method dial*(
    self: MixnetTransportAdapter,
    address: MultiAddress,
    peerId: Opt[PeerId] = Opt.none(PeerId),
): Future[Connection] {.gcsafe.} =
  echo "MixnetTransportAdapter::dial2"
  self.dialWithMixnet(address, peerId)

method upgradeWithMixnet(
    self: MixnetTransportAdapter, conn: MixnetConnectionAdapter, peerId: Opt[PeerId]
): Future[MixnetMuxerAdapter] {.
    base, async, async: (raises: [CancelledError, LPError], raw: true)
.} =
  echo "> MixnetTransportAdapter::upgradeWithMixnet"
  # echo conn.shortLog()
  let muxer = await self.transport.upgrade(conn.connection, peerId)
  echo "< MixnetTransportAdapter::upgradeWithMixnet"
  MixnetMuxerAdapter.new(muxer)

method upgrade*(
    self: MixnetTransportAdapter, conn: MixnetConnectionAdapter, peerId: Opt[PeerId]
): Future[MixnetMuxerAdapter] {.async: (raises: [CancelledError, LPError], raw: true).} =
  echo "# Upgrade"
  echo conn.shortLog()
  self.upgradeWithMixnet(conn, peerId)

method handles*(self: MixnetTransportAdapter, address: MultiAddress): bool {.gcsafe.} =
  echo "# Handles"
  self.transport.handles(address)

proc new*(
    T: typedesc[MixnetTransportAdapter], transport: Transport, upgrade: Upgrade, index, numNodes: int
): MixnetTransportAdapter {.raises: [].} =
  let mixNodeInfo = loadMixNodeInfo(index)
  let pubNodeInfo = loadAllButIndexMixPubInfo(index, numNodes)
  let tagManager = initTagManager()
  T(mixNodeInfo: mixNodeInfo,
    pubNodeInfo: pubNodeInfo,
    transport: transport,
    tagManager: tagManager,
    upgrader: upgrade)
