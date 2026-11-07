/*******************************************************************************
 * YaCT | (c) 2015-2026 Christian Hoppe | http://opensource.org/licenses/MIT
 ******************************************************************************/
package yact.core.stream;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;

import yact.core.crypto.CipherSuite;

/**
 * Prepares the JVM for fast AES-GCM.
 *
 * <p>The JDK's AES-GCM runs at GB/s only once the JIT has compiled the calling
 * code with the processor's AES and carry-less multiplication instructions.
 * A container makes one call per 64 KiB chunk, so without warm-up the first
 * 100-200 MB are encrypted at about 100 MB/s. Warming up the JDK cipher on its
 * own is not enough: the compiled code is only kept for the call path that was
 * exercised, so this runs the container's own stream classes, with small chunks
 * to reach the compile thresholds quickly.
 *
 * <p>Takes about half a second and a few MB of memory. Only a performance
 * measure; nothing depends on it having run.
 */
public final class WarmUp
{
	private static final int CHUNK = 1024;
	private static final int ROUNDS = 10;
	private static final byte[] AAD = "YaCT warm-up".getBytes(StandardCharsets.US_ASCII);

	private WarmUp()
	{
	}

	/** Encrypts and decrypts about 10 MB each with throw-away keys. */
	public static void run()
	{
		byte[] key = new byte[CipherSuite.KEY_LENGTH];
		byte[] data = new byte[1024 * 1024];
		try
		{
			for (int i = 0; i < ROUNDS; i++)
				try (OutputStream out = new ChunkedAeadOutputStream(OutputStream.nullOutputStream(),
						CipherSuite.AES_256_GCM, key, AAD, CHUNK))
				{
					out.write(data);
				}

			ByteArrayOutputStream sealed = new ByteArrayOutputStream();
			try (OutputStream out = new ChunkedAeadOutputStream(sealed, CipherSuite.AES_256_GCM, key, AAD, CHUNK))
			{
				out.write(data);
			}
			byte[] bytes = sealed.toByteArray();
			for (int i = 0; i < ROUNDS; i++)
				try (InputStream in = new ChunkedAeadInputStream(new ByteArrayInputStream(bytes), CipherSuite.AES_256_GCM,
						key, AAD, CHUNK))
				{
					in.transferTo(OutputStream.nullOutputStream());
				}
		}
		catch (IOException e)
		{
			throw new UncheckedIOException(e); // in-memory streams; cannot happen
		}
	}

	/** Starts {@link #run()} on a low-priority daemon thread, e.g. at application start. */
	public static Thread startInBackground()
	{
		Thread t = new Thread(() -> {
			try
			{
				run();
			}
			catch (RuntimeException e)
			{
				// Only a performance measure: any real problem shows up again, with context, on real use.
			}
		}, "yact-crypto-warmup");
		t.setDaemon(true);
		t.setPriority(Thread.MIN_PRIORITY);
		t.start();
		return t;
	}
}
