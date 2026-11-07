/*******************************************************************************
 * YaCT | (c) 2015-2026 Christian Hoppe | http://opensource.org/licenses/MIT
 ******************************************************************************/
package yact.core.crypto;

import java.util.Arrays;

/**
 * Argon2id, version 1.3 (RFC 9106).
 *
 * <p>Implemented here so that no third-party code ever sees a password: a
 * compromised library could otherwise derive keys that ignore the password and
 * make containers openable without it. The structure follows the reference
 * implementation (functions {@code fill_segment}, {@code index_alpha},
 * {@code fill_block}); correctness is checked against the RFC 9106 test vector
 * at runtime ({@link SelfTest}) and against an independent implementation with
 * many parameter combinations in the test suite.
 *
 * <p>Lanes are computed one after another on the calling thread.
 */
final class Argon2id
{
	private static final int VERSION = 0x13;
	private static final int TYPE = 2; // Argon2id
	private static final int SYNC_POINTS = 4;
	private static final int WORDS = 128; // one 1024-byte block
	private static final int ADDRESSES_IN_BLOCK = 128;

	private final int lanes;
	private final int passes;
	private final int laneLength;
	private final int segmentLength;
	private final int blockCount;
	private final long[] memory;
	private final long[] r = new long[WORDS];
	private final long[] tmp = new long[WORDS];
	private final long[] zero = new long[WORDS];
	private final long[] input = new long[WORDS];
	private final long[] address = new long[WORDS];

	private Argon2id(int memoryKiB, int passes, int lanes)
	{
		this.lanes = lanes;
		this.passes = passes;
		this.blockCount = 4 * lanes * (memoryKiB / (4 * lanes));
		this.laneLength = blockCount / lanes;
		this.segmentLength = laneLength / SYNC_POINTS;
		this.memory = new long[Math.multiplyExact(blockCount, WORDS)];
	}

	/**
	 * Computes an Argon2id tag.
	 *
	 * @param secret optional secret value K, may be empty
	 * @param ad     optional associated data X, may be empty
	 */
	static byte[] hash(byte[] password, byte[] salt, byte[] secret, byte[] ad, int memoryKiB, int passes, int lanes,
			int tagLength)
	{
		if (lanes < 1 || lanes > 0xFFFFFF || passes < 1 || memoryKiB < 8 * lanes || tagLength < 4 || salt.length < 8)
			throw new IllegalArgumentException("invalid Argon2 parameters");

		Argon2id a = new Argon2id(memoryKiB, passes, lanes);
		byte[] h0 = Blake2b.hash(64, le32(lanes), le32(tagLength), le32(memoryKiB), le32(passes), le32(VERSION),
				le32(TYPE), le32(password.length), password, le32(salt.length), salt, le32(secret.length), secret,
				le32(ad.length), ad);
		try
		{
			a.initialBlocks(h0);
			for (int pass = 0; pass < passes; pass++)
				for (int slice = 0; slice < SYNC_POINTS; slice++)
					for (int lane = 0; lane < lanes; lane++)
						a.fillSegment(pass, lane, slice);
			return a.finish(tagLength);
		}
		finally
		{
			Arrays.fill(h0, (byte) 0);
			a.wipe();
		}
	}

	private void initialBlocks(byte[] h0)
	{
		for (int lane = 0; lane < lanes; lane++)
			for (int i = 0; i < 2; i++)
			{
				byte[] block = hPrime(1024, h0, le32(i), le32(lane));
				int off = (lane * laneLength + i) * WORDS;
				for (int w = 0; w < WORDS; w++)
					memory[off + w] = Blake2b.le64(block, w * 8);
				Arrays.fill(block, (byte) 0);
			}
	}

	private byte[] finish(int tagLength)
	{
		long[] c = new long[WORDS];
		for (int lane = 0; lane < lanes; lane++)
		{
			int off = (lane * laneLength + laneLength - 1) * WORDS;
			for (int w = 0; w < WORDS; w++)
				c[w] ^= memory[off + w];
		}
		byte[] bytes = new byte[1024];
		for (int w = 0; w < WORDS; w++)
			for (int b = 0; b < 8; b++)
				bytes[w * 8 + b] = (byte) (c[w] >>> (8 * b));
		try
		{
			return hPrime(tagLength, bytes);
		}
		finally
		{
			Arrays.fill(bytes, (byte) 0);
			Arrays.fill(c, 0);
		}
	}

	private void fillSegment(int pass, int lane, int slice)
	{
		boolean dataIndependent = pass == 0 && slice < SYNC_POINTS / 2;
		if (dataIndependent)
		{
			Arrays.fill(input, 0);
			input[0] = pass;
			input[1] = lane;
			input[2] = slice;
			input[3] = blockCount;
			input[4] = passes;
			input[5] = TYPE;
		}

		int start = 0;
		if (pass == 0 && slice == 0)
		{
			start = 2;
			if (dataIndependent)
				nextAddresses();
		}

		int curr = lane * laneLength + slice * segmentLength + start;
		int prev = curr % laneLength == 0 ? curr + laneLength - 1 : curr - 1;
		for (int i = start; i < segmentLength; i++, curr++, prev++)
		{
			if (curr % laneLength == 1)
				prev = curr - 1;

			long pseudoRand;
			if (dataIndependent)
			{
				if (i % ADDRESSES_IN_BLOCK == 0)
					nextAddresses();
				pseudoRand = address[i % ADDRESSES_IN_BLOCK];
			}
			else
				pseudoRand = memory[prev * WORDS];

			int refLane = (int) ((pseudoRand >>> 32) % lanes);
			if (pass == 0 && slice == 0)
				refLane = lane;
			int refIndex = indexAlpha(pass, slice, i, pseudoRand & 0xFFFFFFFFL, refLane == lane);
			int ref = refLane * laneLength + refIndex;
			fillBlock(prev, ref, curr, pass != 0);
		}
	}

	/** Maps the pseudo-random value to a block of the reference lane (RFC 9106, section 3.4.2). */
	private int indexAlpha(int pass, int slice, int index, long j1, boolean sameLane)
	{
		long areaSize;
		if (pass == 0)
		{
			if (slice == 0)
				areaSize = index - 1;
			else if (sameLane)
				areaSize = (long) slice * segmentLength + index - 1;
			else
				areaSize = (long) slice * segmentLength + (index == 0 ? -1 : 0);
		}
		else
		{
			if (sameLane)
				areaSize = laneLength - segmentLength + index - 1;
			else
				areaSize = laneLength - segmentLength + (index == 0 ? -1 : 0);
		}
		// Unsigned 64-bit arithmetic: both factors are below 2^32, products wrap exactly like uint64_t.
		long relative = (j1 * j1) >>> 32;
		relative = areaSize - 1 - ((areaSize * relative) >>> 32);
		long start = 0;
		if (pass != 0)
			start = slice == SYNC_POINTS - 1 ? 0 : (long) (slice + 1) * segmentLength;
		return (int) ((start + relative) % laneLength);
	}

	private void nextAddresses()
	{
		input[6]++;
		compress(zero, input, address);
		compress(zero, address, address);
	}

	/** next = G(prev, ref), XORed into the old content of next from the second pass on. */
	private void fillBlock(int prevBlock, int refBlock, int nextBlock, boolean withXor)
	{
		int p = prevBlock * WORDS;
		int q = refBlock * WORDS;
		int n = nextBlock * WORDS;
		for (int w = 0; w < WORDS; w++)
		{
			r[w] = memory[q + w] ^ memory[p + w];
			tmp[w] = withXor ? r[w] ^ memory[n + w] : r[w];
		}
		permute(r);
		for (int w = 0; w < WORDS; w++)
			memory[n + w] = tmp[w] ^ r[w];
	}

	/** out = G(x, y) for address generation; {@code out} may be {@code y}. */
	private void compress(long[] x, long[] y, long[] out)
	{
		for (int w = 0; w < WORDS; w++)
		{
			r[w] = x[w] ^ y[w];
			tmp[w] = r[w];
		}
		permute(r);
		for (int w = 0; w < WORDS; w++)
			out[w] = tmp[w] ^ r[w];
	}

	/** The permutation P applied to the eight rows, then the eight columns, of a block. */
	private static void permute(long[] v)
	{
		for (int i = 0; i < 8; i++)
		{
			int b = 16 * i;
			round(v, b, b + 1, b + 2, b + 3, b + 4, b + 5, b + 6, b + 7, b + 8, b + 9, b + 10, b + 11, b + 12, b + 13,
					b + 14, b + 15);
		}
		for (int i = 0; i < 8; i++)
		{
			int b = 2 * i;
			round(v, b, b + 1, b + 16, b + 17, b + 32, b + 33, b + 48, b + 49, b + 64, b + 65, b + 80, b + 81, b + 96,
					b + 97, b + 112, b + 113);
		}
	}

	private static void round(long[] v, int v0, int v1, int v2, int v3, int v4, int v5, int v6, int v7, int v8, int v9,
			int v10, int v11, int v12, int v13, int v14, int v15)
	{
		gb(v, v0, v4, v8, v12);
		gb(v, v1, v5, v9, v13);
		gb(v, v2, v6, v10, v14);
		gb(v, v3, v7, v11, v15);
		gb(v, v0, v5, v10, v15);
		gb(v, v1, v6, v11, v12);
		gb(v, v2, v7, v8, v13);
		gb(v, v3, v4, v9, v14);
	}

	private static void gb(long[] v, int a, int b, int c, int d)
	{
		v[a] = blaMka(v[a], v[b]);
		v[d] = Long.rotateRight(v[d] ^ v[a], 32);
		v[c] = blaMka(v[c], v[d]);
		v[b] = Long.rotateRight(v[b] ^ v[c], 24);
		v[a] = blaMka(v[a], v[b]);
		v[d] = Long.rotateRight(v[d] ^ v[a], 16);
		v[c] = blaMka(v[c], v[d]);
		v[b] = Long.rotateRight(v[b] ^ v[c], 63);
	}

	private static long blaMka(long x, long y)
	{
		return x + y + 2 * (x & 0xFFFFFFFFL) * (y & 0xFFFFFFFFL);
	}

	/** H' (RFC 9106, section 3.3): BLAKE2b with arbitrary output length. */
	static byte[] hPrime(int length, byte[]... inputs)
	{
		byte[][] all = new byte[inputs.length + 1][];
		all[0] = le32(length);
		System.arraycopy(inputs, 0, all, 1, inputs.length);
		if (length <= 64)
			return Blake2b.hash(length, all);

		int r = (length + 31) / 32 - 2;
		byte[] out = new byte[length];
		byte[] v = Blake2b.hash(64, all);
		System.arraycopy(v, 0, out, 0, 32);
		int pos = 32;
		for (int i = 2; i <= r; i++)
		{
			byte[] next = Blake2b.hash(64, v);
			Arrays.fill(v, (byte) 0);
			v = next;
			System.arraycopy(v, 0, out, pos, 32);
			pos += 32;
		}
		byte[] last = Blake2b.hash(length - 32 * r, v);
		System.arraycopy(last, 0, out, pos, last.length);
		Arrays.fill(v, (byte) 0);
		Arrays.fill(last, (byte) 0);
		return out;
	}

	private void wipe()
	{
		Arrays.fill(memory, 0);
		Arrays.fill(r, 0);
		Arrays.fill(tmp, 0);
		Arrays.fill(address, 0);
		Arrays.fill(input, 0);
	}

	private static byte[] le32(int v)
	{
		return new byte[] { (byte) v, (byte) (v >>> 8), (byte) (v >>> 16), (byte) (v >>> 24) };
	}
}
