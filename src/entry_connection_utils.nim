import chronos, chronicles
import libp2p/[multiaddress, switch]
import ./[entry_connection, mix_protocol, protocol]
proc createMixEntryConnection*(
    srcMix: MixProtocol, destAddr: MultiAddress, destPeerId: PeerId, codec: string
): MixEntryConnection =
  # Define the sendDialerFunc dynamically for the given sender MixProtocol
  var sendDialerFunc = proc(
      msg: seq[byte],
      proto: ProtocolType,
      destMultiAddr: MultiAddress,
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
