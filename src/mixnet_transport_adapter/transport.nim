import chronos
import libp2p/[stream/connection, transports/transport, upgrademngrs/upgrade]
import ./[connection, muxer]

type MixnetTransportAdapter* = ref object of Transport
  transport: Transport

method log*(self: MixnetTransportAdapter): string {.gcsafe.} =
  "<MixnetTransportAdapter>"

method start*(self: MixnetTransportAdapter, addrs: seq[MultiAddress]) {.async.} =
  echo "# Start"
  await self.transport.start(addrs)
  await procCall self.Transport.start(addrs)

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
    T: typedesc[MixnetTransportAdapter], transport: Transport, upgrade: Upgrade
): MixnetTransportAdapter =
  T(transport: transport, upgrader: upgrade)
