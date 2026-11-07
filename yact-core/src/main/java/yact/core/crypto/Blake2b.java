/*******************************************************************************
 * YaCT | (c) 2015-2026 Christian Hoppe | http://opensource.org/licenses/MIT
 ******************************************************************************/
package yact.core.crypto;

import java.util.Arrays;

/**
 * BLAKE2b (RFC 7693), unkeyed, with an output length of 1 to 64 bytes.
 *
 * <p>Only used inside {@link Argon2id}. It is implemented here so that no
 * third-party code ever processes a password; correctness is checked against
 * the RFC test vector at runtime ({@link SelfTest}) and against an independent
 * implementation in the test suite.
 */
final class Blake2b
{
	private static final long[] IV = {
			0x6a09e667f3bcc908L, 0xbb67ae8584caa73bL, 0x3c6ef372fe94f82bL, 0xa54ff53a5f1d36f1L,
			0x510e527fade682d1L, 0x9b05688c2b3e6c1fL, 0x1f83d9abfb41bd6bL, 0x5be0cd19137e2179L };

	private static final byte[][] SIGMA = {
			{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
			{ 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3 },
			{ 11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4 },
			{ 7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8 },
			{ 9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13 },
			{ 2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9 },
			{ 12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11 },
			{ 13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10 },
			{ 6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5 },
			{ 10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0 } };

	private static final int BLOCK = 128;

	private final int outLength;
	private final long[] h = new long[8];
	private final byte[] buffer = new byte[BLOCK];
	private final long[] m = new long[16];
	private final long[] v = new long[16];
	private int bufferLength;
	private long counter; // bytes compressed so far; inputs here stay far below 2^64

	Blake2b(int outLength)
	{
		if (outLength < 1 || outLength > 64)
			throw new IllegalArgumentException("BLAKE2b output length must be 1..64");
		this.outLength = outLength;
		System.arraycopy(IV, 0, h, 0, 8);
		h[0] ^= 0x01010000L ^ outLength; // parameter block: digest length, no key, fanout 1, depth 1
	}

	/** One-shot hash of the concatenation of {@code inputs}. */
	static byte[] hash(int outLength, byte[]... inputs)
	{
		Blake2b b = new Blake2b(outLength);
		for (byte[] in : inputs)
			b.update(in, 0, in.length);
		return b.digest();
	}

	void update(byte[] in)
	{
		update(in, 0, in.length);
	}

	void update(byte[] in, int off, int len)
	{
		while (len > 0)
		{
			// A full buffer is compressed only when more data follows: the last block must be flagged.
			if (bufferLength == BLOCK)
			{
				counter += BLOCK;
				compress(buffer, false);
				bufferLength = 0;
			}
			int n = Math.min(len, BLOCK - bufferLength);
			System.arraycopy(in, off, buffer, bufferLength, n);
			bufferLength += n;
			off += n;
			len -= n;
		}
	}

	byte[] digest()
	{
		counter += bufferLength;
		Arrays.fill(buffer, bufferLength, BLOCK, (byte) 0);
		compress(buffer, true);
		byte[] out = new byte[outLength];
		for (int i = 0; i < outLength; i++)
			out[i] = (byte) (h[i >>> 3] >>> (8 * (i & 7)));
		Arrays.fill(buffer, (byte) 0);
		Arrays.fill(h, 0);
		Arrays.fill(m, 0);
		Arrays.fill(v, 0);
		return out;
	}

	private void compress(byte[] block, boolean last)
	{
		for (int i = 0; i < 16; i++)
			m[i] = le64(block, i * 8);
		System.arraycopy(h, 0, v, 0, 8);
		System.arraycopy(IV, 0, v, 8, 8);
		v[12] ^= counter;
		// v[13] ^= high 64 bits of the counter, always zero here
		if (last)
			v[14] = ~v[14];
		for (int r = 0; r < 12; r++)
		{
			byte[] s = SIGMA[r % 10];
			g(0, 4, 8, 12, m[s[0]], m[s[1]]);
			g(1, 5, 9, 13, m[s[2]], m[s[3]]);
			g(2, 6, 10, 14, m[s[4]], m[s[5]]);
			g(3, 7, 11, 15, m[s[6]], m[s[7]]);
			g(0, 5, 10, 15, m[s[8]], m[s[9]]);
			g(1, 6, 11, 12, m[s[10]], m[s[11]]);
			g(2, 7, 8, 13, m[s[12]], m[s[13]]);
			g(3, 4, 9, 14, m[s[14]], m[s[15]]);
		}
		for (int i = 0; i < 8; i++)
			h[i] ^= v[i] ^ v[i + 8];
	}

	private void g(int a, int b, int c, int d, long x, long y)
	{
		v[a] = v[a] + v[b] + x;
		v[d] = Long.rotateRight(v[d] ^ v[a], 32);
		v[c] = v[c] + v[d];
		v[b] = Long.rotateRight(v[b] ^ v[c], 24);
		v[a] = v[a] + v[b] + y;
		v[d] = Long.rotateRight(v[d] ^ v[a], 16);
		v[c] = v[c] + v[d];
		v[b] = Long.rotateRight(v[b] ^ v[c], 63);
	}

	static long le64(byte[] b, int off)
	{
		return (b[off] & 0xFFL) | (b[off + 1] & 0xFFL) << 8 | (b[off + 2] & 0xFFL) << 16 | (b[off + 3] & 0xFFL) << 24
				| (b[off + 4] & 0xFFL) << 32 | (b[off + 5] & 0xFFL) << 40 | (b[off + 6] & 0xFFL) << 48
				| (b[off + 7] & 0xFFL) << 56;
	}
}
