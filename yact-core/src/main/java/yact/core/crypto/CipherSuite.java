/*******************************************************************************
 * YaCT | (c) 2015-2026 Christian Hoppe | http://opensource.org/licenses/MIT
 ******************************************************************************/
package yact.core.crypto;

import java.security.GeneralSecurityException;

import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * The authenticated ciphers a container can use for its data and key slots.
 *
 * <p>The numeric {@link #id()} is written to the container header and must
 * never change for an existing constant.
 *
 * <p>Both ciphers come from the JDK's own provider (SunJCE), obtained through
 * {@link JdkCrypto}, which verifies that it is the genuine one. AES uses the
 * processor's AES and carry-less multiplication instructions where available.
 * Output follows NIST SP 800-38D and RFC 8439.
 *
 * <p>The JDK copies the key internally; that copy cannot be wiped and stays on
 * the heap until garbage collection.
 */
public enum CipherSuite
{
	AES_256_GCM(1, "AES-256-GCM"),
	CHACHA20_POLY1305(2, "ChaCha20-Poly1305");

	public static final int KEY_LENGTH = 32;
	public static final int NONCE_LENGTH = 12;
	public static final int TAG_LENGTH = 16;

	private final int id;
	private final String displayName;

	CipherSuite(int id, String displayName)
	{
		this.id = id;
		this.displayName = displayName;
	}

	public int id()
	{
		return id;
	}

	public String displayName()
	{
		return displayName;
	}

	/** Looks up a suite by its header id; {@code null} if unknown. */
	public static CipherSuite byId(int id)
	{
		for (CipherSuite s : values())
			if (s.id == id)
				return s;
		return null;
	}

	/** Name of the implementation in use, for diagnostics. */
	public String implementation()
	{
		return newCipher().getProvider().getName() + " (JDK)";
	}

	/** Encrypts {@code plain} and appends the authentication tag. */
	public byte[] seal(byte[] key, byte[] nonce, byte[] aad, byte[] plain)
	{
		return seal(key, nonce, aad, plain, 0, plain.length);
	}

	/** Encrypts a range of {@code plain} and appends the authentication tag. */
	public byte[] seal(byte[] key, byte[] nonce, byte[] aad, byte[] plain, int off, int len)
	{
		try
		{
			return process(true, key, nonce, aad, plain, off, len);
		}
		catch (AEADBadTagException e)
		{
			throw new IllegalStateException("encryption cannot fail authentication", e);
		}
	}

	/**
	 * Verifies and decrypts {@code sealed} (ciphertext followed by tag).
	 *
	 * @throws AEADBadTagException if the key, nonce, AAD or data do not match
	 */
	public byte[] open(byte[] key, byte[] nonce, byte[] aad, byte[] sealed) throws AEADBadTagException
	{
		return open(key, nonce, aad, sealed, 0, sealed.length);
	}

	/** Verifies and decrypts a range of {@code sealed}. */
	public byte[] open(byte[] key, byte[] nonce, byte[] aad, byte[] sealed, int off, int len)
			throws AEADBadTagException
	{
		return process(false, key, nonce, aad, sealed, off, len);
	}

	private byte[] process(boolean encrypt, byte[] key, byte[] nonce, byte[] aad, byte[] in, int off, int len)
			throws AEADBadTagException
	{
		checkLength("key", key, KEY_LENGTH);
		checkLength("nonce", nonce, NONCE_LENGTH);
		// A fresh instance per call: JCE refuses to encrypt twice with the same key and nonce on
		// one instance, and instances are not thread-safe. Creation is cheap next to the work.
		Cipher cipher = newCipher();
		try
		{
			if (this == AES_256_GCM)
				cipher.init(encrypt ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"),
						new GCMParameterSpec(TAG_LENGTH * 8, nonce));
			else
				cipher.init(encrypt ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE, new SecretKeySpec(key, "ChaCha20"),
						new IvParameterSpec(nonce));
			cipher.updateAAD(aad);
			return cipher.doFinal(in, off, len);
		}
		catch (AEADBadTagException e)
		{
			throw e;
		}
		catch (GeneralSecurityException e)
		{
			// Wrong key size, unavailable algorithm: a programming or installation error, not bad data.
			throw new IllegalStateException(displayName + " is not usable in this runtime", e);
		}
	}

	private Cipher newCipher()
	{
		return JdkCrypto.cipher(this == AES_256_GCM ? "AES/GCM/NoPadding" : "ChaCha20-Poly1305");
	}

	private static void checkLength(String what, byte[] value, int expected)
	{
		if (value == null || value.length != expected)
			throw new IllegalArgumentException(what + " must be " + expected + " bytes");
	}

	@Override
	public String toString()
	{
		return displayName;
	}
}
