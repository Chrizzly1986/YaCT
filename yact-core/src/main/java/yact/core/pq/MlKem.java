/*******************************************************************************
 * YaCT | (c) 2015-2026 Christian Hoppe | http://opensource.org/licenses/MIT
 ******************************************************************************/
package yact.core.pq;

import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.crypto.kems.MLKEMExtractor;
import org.bouncycastle.crypto.kems.MLKEMGenerator;
import org.bouncycastle.crypto.params.MLKEMParameters;
import org.bouncycastle.crypto.params.MLKEMPrivateKeyParameters;
import org.bouncycastle.crypto.params.MLKEMPublicKeyParameters;

import yact.core.crypto.JdkCrypto;

/**
 * ML-KEM (FIPS 203). The only place in YaCT's production code that uses a
 * third-party cryptographic library (BouncyCastle): Java 21 has no ML-KEM.
 *
 * <p>The library is kept away from everything else: it never sees a password,
 * the master key or YaCT's random number generator (the encapsulation
 * randomness m is drawn from the JDK and passed in). Its output is always
 * combined with JDK X25519 ({@link Hybrid}), so even a fully compromised
 * ML-KEM implementation cannot open a container: X25519 still has to be broken.
 * A known-answer self-test checks it before use.
 */
final class MlKem
{
	record Encapsulated(byte[] secret, byte[] ciphertext)
	{
	}

	private MlKem()
	{
	}

	private static MLKEMParameters params(HybridKem kem)
	{
		return switch (kem)
		{
			case MLKEM768_X25519 -> MLKEMParameters.ml_kem_768;
			case MLKEM1024_X25519 -> MLKEMParameters.ml_kem_1024;
		};
	}

	/** Encapsulation key for the 64-byte seed (d ‖ z). */
	static byte[] publicKey(HybridKem kem, byte[] seed)
	{
		return new MLKEMPrivateKeyParameters(params(kem), seed).getPublicKey();
	}

	/** Encapsulation with fresh JDK randomness. */
	static Encapsulated encapsulate(HybridKem kem, byte[] encapsulationKey)
	{
		byte[] m = JdkCrypto.randomBytes(32);
		try
		{
			return encapsulate(kem, encapsulationKey, m);
		}
		finally
		{
			java.util.Arrays.fill(m, (byte) 0);
		}
	}

	/** ML-KEM.Encaps_internal with the given 32-byte m; also used by the known-answer self-test. */
	static Encapsulated encapsulate(HybridKem kem, byte[] encapsulationKey, byte[] m)
	{
		SecretWithEncapsulation s = MLKEMGenerator
				.internalGenerateEncapsulated(new MLKEMPublicKeyParameters(params(kem), encapsulationKey), m);
		return new Encapsulated(s.getSecret(), s.getEncapsulation());
	}

	/** Decapsulation with the key given by its 64-byte seed; implicit rejection for foreign ciphertexts. */
	static byte[] decapsulate(HybridKem kem, byte[] seed, byte[] ciphertext)
	{
		return new MLKEMExtractor(new MLKEMPrivateKeyParameters(params(kem), seed)).extractSecret(ciphertext);
	}

	/** Expanded decapsulation key (FIPS 203 dk) for a seed; for the known-answer self-test. */
	static byte[] expandedDecapsulationKey(HybridKem kem, byte[] seed)
	{
		return new MLKEMPrivateKeyParameters(params(kem), seed)
				.withPreferredFormat(MLKEMPrivateKeyParameters.EXPANDED_KEY).getEncoded();
	}
}
