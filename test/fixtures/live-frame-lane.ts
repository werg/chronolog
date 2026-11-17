import type { PeerFrameLane } from '@chronolog/agent-service/framing'
import { SignalBackpressureError } from '@chronolog/signals'

/** Adapt a dedicated fixture stream; never share it with reliable replication. */
export function liveFrameLane(stream: PeerFrameLane): PeerFrameLane {
  return {
    async send(frame, options) {
      try { await stream.send(frame, options) }
      catch (error) {
        // The bounded framer refuses this send before writing any bytes.
        if (error instanceof Error && error.message === 'PEER_FRAME_BACKPRESSURE') throw new SignalBackpressureError()
        throw error
      }
    },
    frames: signal => stream.frames(signal),
    close: () => stream.close(),
  }
}
