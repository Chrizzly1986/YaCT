/*******************************************************************************
 * YaCT | (c) 2015-2026 Christian Hoppe | http://opensource.org/licenses/MIT
 ******************************************************************************/
package yact.core.crypto;

import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.util.Arrays;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * Key derivation and MAC functions. All outputs are 32 bytes.
 *
 * <p>Only the JDK and YaCT's own code are involved: Argon2id is YaCT's
 * implementation ({@link Argon2id}), HMAC-SHA3-256 comes from the JDK, HKDF is
 * built on it here. No third-party library sees a password or a master key.
 */
public final class Kdf
{
	public static final int OUTPUT_LENGTH = 32;
	private static final String HMAC = "HmacSHA3-256";
	private static final byte[] EMPTY = new byte[0];

	private Kdf()
	{
	}

	/**
	 * Derives a key from a password with Argon2id (version 1.3).
	 *
	 * @param password the password bytes, see {@link Passwords#encode(char[])}
	 * @throws InsufficientMemoryException if the parameters need more memory than is available
	 */
	public static byte[] argon2id(byte[] password, byte[] salt, Argon2Params params)
	{
		ensureMemory(params.memoryBytes());
		return Argon2id.hash(password, salt, EMPTY, EMPTY, params.memoryKiB(), params.iterations(), params.parallelism(),
				OUTPUT_LENGTH);
	}

	/** Throws unless {@code bytes} can be allocated with a safety margin, after a garbage collection if needed. */
	static void ensureMemory(long bytes)
	{
		// An optional lower limit (property "yact.kdf.maxMemoryBytes"); it can only make YaCT refuse more.
		long limit = Long.getLong("yact.kdf.maxMemoryBytes", Long.MAX_VALUE);
		if (bytes > limit)
			throw new InsufficientMemoryException(bytes, limit);
		Runtime rt = Runtime.getRuntime();
		long needed = bytes + (16L << 20); // working buffers and headroom
		if (available(rt) < needed)
		{
			System.gc();
			if (available(rt) < needed)
				throw new InsufficientMemoryException(bytes, available(rt));
		}
	}

	private static long available(Runtime rt)
	{
		return rt.maxMemory() - (rt.totalMemory() - rt.freeMemory());
	}

	/**
	 * HKDF (RFC 5869) over HMAC-SHA3-256, one output block.
	 *
	 * @param ikm     input key material
	 * @param salt    optional salt, may be {@code null}
	 * @param label   purpose label; every purpose uses its own label
	 * @param context further values bound into the output, length-prefixed
	 */
	public static byte[] hkdf(byte[] ikm, byte[] salt, String label, byte[]... context)
	{
		// RFC 5869: a missing salt is HashLen zero bytes.
		byte[] s = salt == null || salt.length == 0 ? new byte[OUTPUT_LENGTH] : salt;
		byte[] prk = hmac(s, ikm, 0, ikm.length);
		try
		{
			Mac mac = mac(prk);
			mac.update(info(label, context));
			mac.update((byte) 1);
			return mac.doFinal(); // T(1): exactly OUTPUT_LENGTH bytes
		}
		finally
		{
			Arrays.fill(prk, (byte) 0);
		}
	}

	/** HMAC-SHA3-256. */
	public static byte[] hmac(byte[] key, byte[] data, int off, int len)
	{
		Mac mac = mac(key);
		mac.update(data, off, len);
		return mac.doFinal();
	}

	private static Mac mac(byte[] key)
	{
		Mac mac = JdkCrypto.hmacSha3_256();
		try
		{
			mac.init(new SecretKeySpec(key, HMAC));
		}
		catch (InvalidKeyException e)
		{
			throw new IllegalStateException(e);
		}
		return mac;
	}

	/** Label bytes followed by each context element, each prefixed with its 2-byte length. */
	private static byte[] info(String label, byte[]... context)
	{
		byte[] l = label.getBytes(StandardCharsets.US_ASCII);
		int size = 2 + l.length;
		for (byte[] c : context)
			size += 2 + c.length;
		byte[] out = new byte[size];
		int p = put(out, 0, l);
		for (byte[] c : context)
			p = put(out, p, c);
		return out;
	}

	private static int put(byte[] out, int p, byte[] value)
	{
		if (value.length > 0xFFFF)
			throw new IllegalArgumentException("context element too long");
		out[p++] = (byte) (value.length >>> 8);
		out[p++] = (byte) value.length;
		System.arraycopy(value, 0, out, p, value.length);
		return p + value.length;
	}
}
