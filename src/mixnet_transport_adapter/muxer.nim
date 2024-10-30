import chronos
import libp2p/[stream/connection, muxers/muxer]

type MixnetMuxerAdapter* = ref object of Muxer
  muxer: Muxer

func shortLog*(self: MixnetMuxerAdapter): auto =
  self.muxer.shortLog()

method newStream*(
    self: MixnetMuxerAdapter, name: string = "", lazy: bool = false
): Future[Connection] {.
    async: (raises: [CancelledError, LPStreamError, MuxerError], raw: true)
.} =
  self.muxer.newStream(name, lazy)

method close*(self: MixnetMuxerAdapter) {.async: (raises: []).} =
  self.muxer.close()

method handle*(self: MixnetMuxerAdapter): Future[void] {.async: (raises: []).} =
  self.muxer.handle()

method getStreams*(self: MixnetMuxerAdapter): seq[Connection] =
  self.muxer.getStreams()

proc new*(T: typedesc[MixnetMuxerAdapter], muxer: Muxer): MixnetMuxerAdapter =
  T(muxer: muxer)
