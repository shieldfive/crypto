/**
 * A FIFO byte queue for the streaming encoders/decoders.
 *
 * The streams used to keep their pending bytes in a plain Uint8Array and
 * rebuild it on every append (`new Uint8Array(a.length + b.length)`) and
 * on every consume (`buffer.subarray(n).slice(0)`). Both copy everything
 * still buffered, so a stream fed in many small pieces — or a decoder
 * holding a 5 MiB chunk while it arrives in 16 KiB network reads — did
 * O(n²) copying.
 *
 * This keeps one backing buffer with a read offset and a write offset.
 * Appends grow it geometrically (or compact it in place when the dead
 * prefix is large enough), so every byte is copied O(1) times amortised.
 * `take(n)` returns an independent copy, exactly like the old `consume`.
 */
export class ByteQueue {
  private buf: Uint8Array
  private start = 0
  private end = 0

  constructor(initialCapacity = 0) {
    this.buf = new Uint8Array(initialCapacity)
  }

  /** Number of buffered (unread) bytes. */
  get length(): number {
    return this.end - this.start
  }

  /** Append a copy of `input`. */
  append(input: Uint8Array): void {
    const n = input.length
    if (n === 0) return
    if (this.end + n > this.buf.length) {
      const live = this.end - this.start
      const needed = live + n
      if (needed <= this.buf.length && this.start >= live) {
        // Enough room once the dead prefix is reclaimed, and the live
        // part is no larger than the prefix, so the move is cheap.
        this.buf.copyWithin(0, this.start, this.end)
      } else {
        const next = new Uint8Array(Math.max(needed, this.buf.length * 2, 64))
        next.set(this.buf.subarray(this.start, this.end), 0)
        this.buf = next
      }
      this.start = 0
      this.end = live
    }
    this.buf.set(input, this.end)
    this.end += n
  }

  /** The byte at `index` (relative to the read offset). */
  byteAt(index: number): number {
    if (index < 0 || index >= this.length) {
      throw new RangeError('ByteQueue.byteAt: index out of range')
    }
    return this.buf[this.start + index]!
  }

  /** Remove and return the first `n` bytes as an independent copy. */
  take(n: number): Uint8Array {
    if (n < 0 || n > this.length) {
      throw new RangeError('ByteQueue.take: not enough buffered bytes')
    }
    const out = this.buf.slice(this.start, this.start + n)
    this.start += n
    if (this.start === this.end) {
      this.start = 0
      this.end = 0
    }
    return out
  }

  /** Remove and return everything buffered as an independent copy. */
  takeAll(): Uint8Array {
    return this.take(this.length)
  }

  /** Overwrite the backing store with zeros and empty the queue. */
  wipe(): void {
    this.buf.fill(0)
    this.start = 0
    this.end = 0
  }
}
