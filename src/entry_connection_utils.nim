import chronos, chronicles
import std/options
import libp2p/[multiaddress, switch]
import ./[entry_connection, mix_protocol, protocol]
proc createMixEntryConnection*(
    srcMix: MixProtocol,
    destAddr: Option[MultiAddress],
    destPeerId: PeerId,
    codec: string,
): MixEntryConnection {.gcsafe, raises: [].} =
  var sendDialerFunc = proc(
      msg: seq[byte],
      proto: ProtocolType,
      destMultiAddr: Option[MultiAddress],
      destPeerId: PeerId,
  ): Future[void] {.async: (raises: [CancelledError, LPStreamError]).} =
    try:
      await srcMix.anonymizeLocalProtocolSend(msg, proto, destMultiAddr, destPeerId)
    except CatchableError as e:
      error "Error during execution of anonymizeLocalProtocolSend: ", err = e.msg
    return

  # Create and return a new MixEntryConnection
  MixEntryConnection.new(
    destAddr, destPeerId, ProtocolType.fromString(codec), sendDialerFunc
  )
