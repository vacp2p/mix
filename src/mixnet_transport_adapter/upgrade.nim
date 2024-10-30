import chronos
import libp2p/[upgrademngrs/upgrade, muxers/muxer]
import ./connection

type MixnetUpgradeAdapter* = ref object of Upgrade
  upgrade: Upgrade

method upgrade*(
    self: MixnetUpgradeAdapter, conn: Connection, peerId: Opt[PeerId]
): Future[Muxer] {.async: (raises: [CancelledError, LPError], raw: true).} =
  assert conn of MixnetConnectionAdapter
  # No other kind of connection should arrive here.
  # If it arrives, it's due to poor Switch configuration.
  # TODO: Some way to prevent this without using an 'if'?
  echo "> MixnetUpgradeAdapter::upgrade"
  self.upgrade.upgrade(conn.MixnetConnectionAdapter.connection, peerId)

method secure*(
    self: MixnetUpgradeAdapter, conn: Connection, peerId: Opt[PeerId]
): Future[Connection] {.async: (raises: [CancelledError, LPError]).} =
  assert conn of MixnetConnectionAdapter
  # No other kind of connection should arrive here.
  # If it arrives, it's due to poor Switch configuration.
  # TODO: Some way to prevent this without using an 'if'?
  echo "> MixnetUpgradeAdapter::secure"
  await self.upgrade.secure(conn.MixnetConnectionAdapter.connection, peerId)

proc new*(T: typedesc[MixnetUpgradeAdapter], upgrade: Upgrade): MixnetUpgradeAdapter =
  T(upgrade: upgrade, ms: upgrade.ms, secureManagers: upgrade.secureManagers)
