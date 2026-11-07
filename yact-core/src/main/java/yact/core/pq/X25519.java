/*******************************************************************************
 * YaCT | (c) 2015-2026 Christian Hoppe | http://opensource.org/licenses/MIT
 ******************************************************************************/
package yact.core.pq;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.NamedParameterSpec;
import java.security.spec.XECPrivateKeySpec;
import java.security.spec.XECPublicKeySpec;

import javax.crypto.KeyAgreement;

import yact.core.crypto.JdkCrypto;

/** X25519 (RFC 7748) on raw 32-byte keys, computed by the JDK. */
final class X25519
{
	static final int KEY_LENGTH = 32;
	private static final byte[] BASE_POINT = basePoint();

	private X25519()
	{
	}

	/** The public key of a 32-byte private scalar (clamped by the JDK as RFC 7748 requires). */
	static byte[] publicKey(byte[] scalar)
	{
		try
		{
			return agree(scalar, BASE_POINT);
		}
		catch (InvalidKeyException e)
		{
			throw new IllegalStateException("the base point cannot have small order", e);
		}
	}

	/**
	 * The shared secret X25519(scalar, peer).
	 *
	 * @throws InvalidKeyException if {@code peer} is a point of small order, which would
	 *                             give an all-zero secret for every scalar
	 */
	static byte[] agree(byte[] scalar, byte[] peer) throws InvalidKeyException
	{
		if (scalar.length != KEY_LENGTH || peer.length != KEY_LENGTH)
			throw new IllegalArgumentException("X25519 keys are 32 bytes");
		try
		{
			KeyFactory kf = JdkCrypto.x25519KeyFactory();
			PrivateKey priv = kf.generatePrivate(new XECPrivateKeySpec(NamedParameterSpec.X25519, scalar.clone()));
			PublicKey pub = kf.generatePublic(new XECPublicKeySpec(NamedParameterSpec.X25519, decodeU(peer)));
			KeyAgreement ka = JdkCrypto.x25519Agreement();
			ka.init(priv);
			ka.doPhase(pub, true);
			return ka.generateSecret();
		}
		catch (InvalidKeyException e)
		{
			throw e;
		}
		catch (GeneralSecurityException e)
		{
			throw new IllegalStateException("X25519 failed", e);
		}
	}

	/** RFC 7748, section 5: little-endian, most significant bit ignored. */
	private static BigInteger decodeU(byte[] u)
	{
		byte[] be = new byte[KEY_LENGTH];
		for (int i = 0; i < KEY_LENGTH; i++)
			be[i] = u[KEY_LENGTH - 1 - i];
		be[0] &= 0x7F;
		return new BigInteger(1, be);
	}

	private static byte[] basePoint()
	{
		byte[] b = new byte[KEY_LENGTH];
		b[0] = 9;
		return b;
	}
}
