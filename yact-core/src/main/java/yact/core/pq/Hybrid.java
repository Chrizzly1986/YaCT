/*******************************************************************************
 * YaCT | (c) 2015-2026 Christian Hoppe | http://opensource.org/licenses/MIT
 ******************************************************************************/
package yact.core.pq;

import java.security.InvalidKeyException;
import java.security.SecureRandom;
import java.util.Arrays;

import yact.core.crypto.JdkCrypto;
import yact.core.crypto.Kdf;
import yact.core.crypto.Passwords;

/**
 * Hybrid key encapsulation: ML-KEM and ephemeral-static X25519, combined
 * into one 32-byte key.
 *
 * <pre>
 * key = HKDF-SHA3-256(
 *         ikm  = ss_mlkem ‖ ss_x25519,
 *         salt = context,
 *         info = "YaCT v1 hybrid kem", scheme id, ct_mlkem, ephemeral_x25519,
 *                recipient_x25519, recipient_mlkem)
 * </pre>
 *
 * <p>Both shared secrets and every ciphertext and public key enter the KDF,
 * the generic combiner that stays secure if either component is broken
 * (Giacon, Heuer, Poettering, "KEM Combiners", PKC 2018; see also NIST SP 800-227).
 * An attacker must break both ML-KEM and X25519 to learn the key.
 *
 * <p>X25519 and all key derivation run in the JDK; only ML-KEM comes from a
 * third-party library ({@link MlKem}). A compromised ML-KEM implementation
 * alone therefore cannot open a container.
 */
public final class Hybrid
{
	private static final String LABEL = "YaCT v1 hybrid kem";

	private Hybrid()
	{
	}

	/** Output of {@link #encapsulate}: the key, and the two values the recipient needs. */
	public record Encapsulation(byte[] key, byte[] x25519Ephemeral, byte[] mlKemCiphertext)
	{
	}

	/**
	 * Creates a fresh key for {@code recipient}.
	 *
	 * @param context bound into the key, e.g. the container id
	 * @param random  unused; all randomness comes from {@link JdkCrypto#random()}. Kept for API stability.
	 */
	public static Encapsulation encapsulate(HybridPublicKey recipient, byte[] context, SecureRandom random)
	{
		MlKem.Encapsulated mlKem = MlKem.encapsulate(recipient.kem(), recipient.mlKem());

		byte[] ephPrivate = JdkCrypto.randomBytes(X25519.KEY_LENGTH);
		byte[] ephPublic = X25519.publicKey(ephPrivate);
		byte[] ssX;
		try
		{
			ssX = X25519.agree(ephPrivate, recipient.x25519());
		}
		catch (InvalidKeyException e)
		{
			throw new IllegalArgumentException("invalid recipient X25519 key", e); // excluded by HybridPublicKey
		}
		finally
		{
			Passwords.wipe(ephPrivate);
		}

		byte[] ssM = mlKem.secret();
		try
		{
			return new Encapsulation(combine(recipient, ssM, ssX, mlKem.ciphertext(), ephPublic, context), ephPublic,
					mlKem.ciphertext());
		}
		finally
		{
			Passwords.wipe(ssM, ssX);
		}
	}

	/**
	 * Recovers the key.
	 *
	 * <p>ML-KEM uses implicit rejection: for a ciphertext not made for this key
	 * the result is a random-looking key rather than an error. Callers detect
	 * the mismatch when the key fails to authenticate data.
	 *
	 * @return the key, or {@code null} if {@code x25519Ephemeral} is invalid
	 */
	public static byte[] decapsulate(HybridKeyPair key, byte[] x25519Ephemeral, byte[] mlKemCiphertext, byte[] context)
	{
		HybridKem kem = key.kem();
		if (x25519Ephemeral.length != HybridKem.X25519_KEY_LENGTH || mlKemCiphertext.length != kem.mlKemCiphertextLength())
			throw new IllegalArgumentException("encapsulation has the wrong length for " + kem);

		byte[] scalar = key.x25519Private();
		byte[] seed = key.mlKemSeed();
		byte[] ssX;
		try
		{
			ssX = X25519.agree(scalar, x25519Ephemeral);
		}
		catch (InvalidKeyException e)
		{
			Passwords.wipe(seed);
			return null;
		}
		finally
		{
			Passwords.wipe(scalar);
		}
		byte[] ssM;
		try
		{
			ssM = MlKem.decapsulate(kem, seed, mlKemCiphertext);
		}
		finally
		{
			Passwords.wipe(seed);
		}
		try
		{
			return combine(key.publicKey(), ssM, ssX, mlKemCiphertext, x25519Ephemeral, context);
		}
		finally
		{
			Passwords.wipe(ssM, ssX);
		}
	}

	static byte[] combine(HybridPublicKey recipient, byte[] ssM, byte[] ssX, byte[] ct, byte[] ephPublic,
			byte[] context)
	{
		byte[] ikm = Arrays.copyOf(ssM, ssM.length + ssX.length);
		System.arraycopy(ssX, 0, ikm, ssM.length, ssX.length);
		try
		{
			return Kdf.hkdf(ikm, context, LABEL, new byte[] { (byte) recipient.kem().id() }, ct, ephPublic,
					recipient.x25519(), recipient.mlKem());
		}
		finally
		{
			Passwords.wipe(ikm);
		}
	}
}
