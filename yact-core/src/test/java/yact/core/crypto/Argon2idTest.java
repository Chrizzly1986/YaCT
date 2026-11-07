/*******************************************************************************
 * YaCT | (c) 2015-2026 Christian Hoppe | http://opensource.org/licenses/MIT
 ******************************************************************************/
package yact.core.crypto;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import java.util.Arrays;
import java.util.Random;

import org.bouncycastle.crypto.digests.Blake2bDigest;
import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.Test;

/**
 * YaCT's own BLAKE2b and Argon2id against the official test vectors and, as a
 * differential test, against BouncyCastle as an independent implementation.
 */
class Argon2idTest
{
	/** RFC 7693, appendix A. */
	@Test
	void blake2bKnownAnswer()
	{
		assertArrayEquals(Hex.decode("ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d1"
				+ "7d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923"), Blake2b.hash(64, "abc".getBytes()));
	}

	@Test
	void blake2bMatchesIndependentImplementation()
	{
		Random rnd = new Random(1);
		for (int i = 0; i < 2000; i++)
		{
			int outLen = 1 + rnd.nextInt(64);
			byte[] in = new byte[rnd.nextInt(600)];
			rnd.nextBytes(in);
			Blake2bDigest bc = new Blake2bDigest(outLen * 8);
			bc.update(in, 0, in.length);
			byte[] expected = new byte[outLen];
			bc.doFinal(expected, 0);

			// Feed in random pieces to exercise the buffering across block boundaries.
			Blake2b ours = new Blake2b(outLen);
			int pos = 0;
			while (pos < in.length)
			{
				int n = Math.min(in.length - pos, 1 + rnd.nextInt(200));
				ours.update(in, pos, n);
				pos += n;
			}
			assertArrayEquals(expected, ours.digest(), "length " + in.length + ", out " + outLen);
		}
	}

	/** RFC 9106, section 5.3. */
	@Test
	void argon2idKnownAnswer()
	{
		byte[] tag = Argon2id.hash(fill(32, 1), fill(16, 2), fill(8, 3), fill(12, 4), 32, 3, 4, 32);
		assertArrayEquals(Hex.decode("0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659"), tag);
	}

	@Test
	void argon2idMatchesIndependentImplementation()
	{
		Random rnd = new Random(2);
		for (int i = 0; i < 150; i++)
		{
			int lanes = 1 + rnd.nextInt(4);
			int memory = 8 * lanes + rnd.nextInt(300);
			int passes = 1 + rnd.nextInt(4);
			int tagLength = 4 + rnd.nextInt(i % 10 == 0 ? 300 : 60); // sometimes beyond 64 bytes: H' branch
			byte[] pw = bytes(rnd, rnd.nextInt(40));
			byte[] salt = bytes(rnd, 8 + rnd.nextInt(32));
			byte[] secret = bytes(rnd, rnd.nextInt(3) == 0 ? rnd.nextInt(20) : 0);
			byte[] ad = bytes(rnd, rnd.nextInt(3) == 0 ? rnd.nextInt(20) : 0);

			Argon2BytesGenerator bc = new Argon2BytesGenerator();
			bc.init(new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id).withVersion(Argon2Parameters.ARGON2_VERSION_13)
					.withSalt(salt).withSecret(secret).withAdditional(ad).withMemoryAsKB(memory).withIterations(passes)
					.withParallelism(lanes).build());
			byte[] expected = new byte[tagLength];
			bc.generateBytes(pw, expected);

			assertArrayEquals(expected, Argon2id.hash(pw, salt, secret, ad, memory, passes, lanes, tagLength),
					"m=" + memory + " t=" + passes + " p=" + lanes + " len=" + tagLength);
		}
	}

	@Test
	void argon2idProductionParametersMatch()
	{
		byte[] pw = "correct horse battery staple".getBytes();
		byte[] salt = fill(16, 7);
		Argon2BytesGenerator bc = new Argon2BytesGenerator();
		bc.init(new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id).withVersion(Argon2Parameters.ARGON2_VERSION_13)
				.withSalt(salt).withMemoryAsKB(Argon2Params.DEFAULT.memoryKiB())
				.withIterations(Argon2Params.DEFAULT.iterations()).withParallelism(Argon2Params.DEFAULT.parallelism())
				.build());
		byte[] expected = new byte[32];
		bc.generateBytes(pw, expected);
		assertArrayEquals(expected, Kdf.argon2id(pw, salt, Argon2Params.DEFAULT));
	}

	private static byte[] bytes(Random rnd, int n)
	{
		byte[] b = new byte[n];
		rnd.nextBytes(b);
		return b;
	}

	private static byte[] fill(int n, int v)
	{
		byte[] b = new byte[n];
		Arrays.fill(b, (byte) v);
		return b;
	}
}
