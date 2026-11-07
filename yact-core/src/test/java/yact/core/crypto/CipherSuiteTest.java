/*******************************************************************************
 * YaCT | (c) 2015-2026 Christian Hoppe | http://opensource.org/licenses/MIT
 ******************************************************************************/
package yact.core.crypto;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.security.SecureRandom;
import java.util.Arrays;

import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.ValueSource;

class CipherSuiteTest
{
	private static final SecureRandom RANDOM = new SecureRandom();

	@Test
	void aesUsesTheJdkProvider()
	{
		assertEquals("SunJCE", CipherSuite.AES_256_GCM.implementation());
	}

	/**
	 * The JDK implementation must produce exactly what BouncyCastle produces,
	 * byte for byte, in both directions: the file format does not depend on it.
	 */
	@ParameterizedTest
	@ValueSource(ints = { 0, 1, 15, 16, 17, 1000, 65536 })
	void jdkAesGcmMatchesBouncyCastle(int length) throws InvalidCipherTextException
	{
		byte[] key = random(32);
		byte[] nonce = random(12);
		byte[] aad = random(length % 50);
		byte[] plain = random(length);

		byte[] jdk = CipherSuite.AES_256_GCM.seal(key, nonce, aad, plain);
		byte[] bc = bouncyCastleGcm(true, key, nonce, aad, plain);
		assertArrayEquals(bc, jdk);
		assertArrayEquals(plain, bouncyCastleGcm(false, key, nonce, aad, jdk));
		assertArrayEquals(plain, CipherSuite.AES_256_GCM.open(key, nonce, aad, bc));
	}

	/** McGrew/Viega GCM spec, test case 16: AES-256, 60-byte plaintext, 20-byte AAD. */
	@Test
	void aes256GcmKnownAnswerWithAad() throws InvalidCipherTextException
	{
		byte[] key = Hex.decode("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308");
		byte[] nonce = Hex.decode("cafebabefacedbaddecaf888");
		byte[] aad = Hex.decode("feedfacedeadbeeffeedfacedeadbeefabaddad2");
		byte[] plain = Hex.decode("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39");
		byte[] expected = Hex.decode("522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662"
				+ "76fc6ece0f4e1768cddf8853bb2d551b");

		assertArrayEquals(expected, CipherSuite.AES_256_GCM.seal(key, nonce, aad, plain));
		assertArrayEquals(plain, CipherSuite.AES_256_GCM.open(key, nonce, aad, expected));
	}

	@ParameterizedTest
	@EnumSource(CipherSuite.class)
	void rangesAndTampering(CipherSuite suite) throws InvalidCipherTextException
	{
		byte[] key = random(32);
		byte[] nonce = random(12);
		byte[] buffer = random(100);
		byte[] sealed = suite.seal(key, nonce, new byte[0], buffer, 10, 50);
		assertArrayEquals(Arrays.copyOfRange(buffer, 10, 60), suite.open(key, nonce, new byte[0], sealed));

		byte[] padded = new byte[sealed.length + 7];
		System.arraycopy(sealed, 0, padded, 3, sealed.length);
		assertArrayEquals(Arrays.copyOfRange(buffer, 10, 60), suite.open(key, nonce, new byte[0], padded, 3, sealed.length));

		sealed[sealed.length - 1] ^= 1;
		assertThrows(InvalidCipherTextException.class, () -> suite.open(key, nonce, new byte[0], sealed));
		assertThrows(InvalidCipherTextException.class, () -> suite.open(key, nonce, new byte[0], new byte[5]));
		assertThrows(IllegalArgumentException.class, () -> suite.seal(new byte[16], nonce, new byte[0], buffer));
		assertThrows(IllegalArgumentException.class, () -> suite.seal(key, new byte[8], new byte[0], buffer));
	}

	/** The same key and nonce may be used again in a later call, e.g. to re-encrypt identical data in tests. */
	@Test
	void freshCipherPerCall()
	{
		byte[] key = random(32);
		byte[] nonce = random(12);
		byte[] plain = random(20);
		assertArrayEquals(CipherSuite.AES_256_GCM.seal(key, nonce, new byte[0], plain),
				CipherSuite.AES_256_GCM.seal(key, nonce, new byte[0], plain));
	}

	private static byte[] bouncyCastleGcm(boolean encrypt, byte[] key, byte[] nonce, byte[] aad, byte[] in)
			throws InvalidCipherTextException
	{
		GCMBlockCipher c = (GCMBlockCipher) GCMBlockCipher.newInstance(AESEngine.newInstance());
		c.init(encrypt, new AEADParameters(new KeyParameter(key), 128, nonce, aad));
		byte[] out = new byte[c.getOutputSize(in.length)];
		int n = c.processBytes(in, 0, in.length, out, 0);
		n += c.doFinal(out, n);
		return Arrays.copyOf(out, n);
	}

	private static byte[] random(int n)
	{
		byte[] b = new byte[n];
		RANDOM.nextBytes(b);
		return b;
	}
}
