/*******************************************************************************
 * YaCT | (c) 2015-2026 Christian Hoppe | http://opensource.org/licenses/MIT
 ******************************************************************************/
package yact.core.crypto;

import java.security.GeneralSecurityException;
import java.security.Provider;
import java.security.Security;
import java.util.Arrays;

import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.modes.AEADCipher;
import org.bouncycastle.crypto.modes.ChaCha20Poly1305;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;

/**
 * The authenticated ciphers a container can use for its data and key slots.
 *
 * <p>The numeric {@link #id()} is written to the container header and must
 * never change for an existing constant.
 *
 * <p>Implementations: AES-256-GCM uses the JDK's own provider (SunJCE), which
 * uses the processor's AES and carry-less multiplication instructions where
 * available. ChaCha20-Poly1305 uses BouncyCastle. Both produce the standard
 * output (NIST SP 800-38D, RFC 8439), so the choice of implementation does not
 * affect the file format.
 *
 * <p>Both implementations copy the key internally; those copies cannot be
 * wiped and stay on the heap until garbage collection.
 */
public enum CipherSuite
{
	AES_256_GCM(1, "AES-256-GCM"),
	CHACHA20_POLY1305(2, "ChaCha20-Poly1305");

	public static final int KEY_LENGTH = 32;
	public static final int NONCE_LENGTH = 12;
	public static final int TAG_LENGTH = 16;

	private static final String AES_GCM_TRANSFORMATION = "AES/GCM/NoPadding";

	/**
	 * The JDK's provider, requested by name so that another provider registered
	 * first (e.g. BouncyCastle) is not picked by accident. {@code null} if this
	 * runtime has no SunJCE; then the default provider is used.
	 */
	private static final Provider JDK_PROVIDER = Security.getProvider("SunJCE");

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
		return switch (this)
		{
			case AES_256_GCM -> newAesGcm().getProvider().getName();
			case CHACHA20_POLY1305 -> "BouncyCastle";
		};
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
		catch (InvalidCipherTextException e)
		{
			throw new IllegalStateException("encryption cannot fail authentication", e);
		}
	}

	/**
	 * Verifies and decrypts {@code sealed} (ciphertext followed by tag).
	 *
	 * @throws InvalidCipherTextException if the key, nonce, AAD or data do not match
	 */
	public byte[] open(byte[] key, byte[] nonce, byte[] aad, byte[] sealed) throws InvalidCipherTextException
	{
		return open(key, nonce, aad, sealed, 0, sealed.length);
	}

	/** Verifies and decrypts a range of {@code sealed}. */
	public byte[] open(byte[] key, byte[] nonce, byte[] aad, byte[] sealed, int off, int len)
			throws InvalidCipherTextException
	{
		return process(false, key, nonce, aad, sealed, off, len);
	}

	private byte[] process(boolean encrypt, byte[] key, byte[] nonce, byte[] aad, byte[] in, int off, int len)
			throws InvalidCipherTextException
	{
		checkLength("key", key, KEY_LENGTH);
		checkLength("nonce", nonce, NONCE_LENGTH);
		return switch (this)
		{
			case AES_256_GCM -> aesGcm(encrypt, key, nonce, aad, in, off, len);
			case CHACHA20_POLY1305 -> bouncyCastle(new ChaCha20Poly1305(), encrypt, key, nonce, aad, in, off, len);
		};
	}

	private static byte[] aesGcm(boolean encrypt, byte[] key, byte[] nonce, byte[] aad, byte[] in, int off, int len)
			throws InvalidCipherTextException
	{
		// A fresh instance per call: JCE refuses to encrypt twice with the same key and nonce on
		// one instance, and instances are not thread-safe. Creation is cheap next to the work.
		Cipher cipher = newAesGcm();
		try
		{
			cipher.init(encrypt ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"),
					new GCMParameterSpec(TAG_LENGTH * 8, nonce));
			cipher.updateAAD(aad);
			return cipher.doFinal(in, off, len);
		}
		catch (AEADBadTagException e)
		{
			throw new InvalidCipherTextException("authentication failed", e);
		}
		catch (GeneralSecurityException e)
		{
			// Wrong key size, unavailable algorithm: a programming or installation error, not bad data.
			throw new IllegalStateException("AES-GCM is not usable in this runtime", e);
		}
	}

	private static Cipher newAesGcm()
	{
		try
		{
			return JDK_PROVIDER != null
					? Cipher.getInstance(AES_GCM_TRANSFORMATION, JDK_PROVIDER)
					: Cipher.getInstance(AES_GCM_TRANSFORMATION);
		}
		catch (GeneralSecurityException e)
		{
			throw new IllegalStateException("AES-GCM is not available in this runtime", e);
		}
	}

	private static byte[] bouncyCastle(AEADCipher cipher, boolean encrypt, byte[] key, byte[] nonce, byte[] aad,
			byte[] in, int off, int len) throws InvalidCipherTextException
	{
		cipher.init(encrypt, new AEADParameters(new KeyParameter(key), TAG_LENGTH * 8, nonce, aad));
		byte[] out = new byte[cipher.getOutputSize(len)];
		int n = cipher.processBytes(in, off, len, out, 0);
		n += cipher.doFinal(out, n);
		return n == out.length ? out : Arrays.copyOf(out, n);
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
