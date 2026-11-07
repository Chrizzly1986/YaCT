/*******************************************************************************
 * YaCT | (c) 2015-2026 Christian Hoppe | http://opensource.org/licenses/MIT
 ******************************************************************************/
package yact.core.container;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.security.GeneralSecurityException;
import java.util.List;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Overwrites file regions with random data that cannot be told apart from
 * ciphertext.
 *
 * <p>The data is an AES-256-CTR keystream under a fresh random key: a
 * cryptographically secure generator that runs at disk speed thanks to the
 * processor's AES instructions, unlike {@code SecureRandom}.
 */
final class RandomFill
{
	private static final int BUFFER = 1 << 20;

	private RandomFill()
	{
	}

	/** Fills all {@code extents}; reports progress over their total length. */
	static void fill(FileChannel ch, List<Extent> extents, ProgressListener progress) throws IOException
	{
		long total = 0;
		for (Extent e : extents)
			total += e.length();
		long done = 0;
		progress.progress(0, total);

		Cipher ctr = newKeystream();
		byte[] zeros = new byte[BUFFER];
		byte[] out = new byte[BUFFER];
		for (Extent e : extents)
		{
			for (long pos = e.offset(); pos < e.end();)
			{
				int n = (int) Math.min(BUFFER, e.end() - pos);
				try
				{
					ctr.update(zeros, 0, n, out, 0);
				}
				catch (javax.crypto.ShortBufferException ex)
				{
					throw new IllegalStateException(ex); // out is as large as the input
				}
				ByteBuffer buf = ByteBuffer.wrap(out, 0, n);
				while (buf.hasRemaining())
					pos += ch.write(buf, pos);
				done += n;
				progress.progress(done, total);
			}
		}
	}

	private static Cipher newKeystream()
	{
		byte[] key = yact.core.crypto.JdkCrypto.randomBytes(32);
		byte[] iv = yact.core.crypto.JdkCrypto.randomBytes(16);
		try
		{
			Cipher c = yact.core.crypto.JdkCrypto.cipher("AES/CTR/NoPadding");
			c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
			return c;
		}
		catch (GeneralSecurityException e)
		{
			throw new IllegalStateException("AES-CTR is not available", e);
		}
		finally
		{
			java.util.Arrays.fill(key, (byte) 0);
		}
	}
}
