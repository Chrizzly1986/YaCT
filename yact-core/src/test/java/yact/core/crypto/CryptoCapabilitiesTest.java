/*******************************************************************************
 * YaCT | (c) 2015-2026 Christian Hoppe | http://opensource.org/licenses/MIT
 ******************************************************************************/
package yact.core.crypto;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.Provider;
import java.security.Security;
import java.util.List;
import java.util.Random;
import java.util.Set;
import java.util.stream.Collectors;

import javax.crypto.CipherSpi;

import org.bouncycastle.crypto.digests.SHA3Digest;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.HKDFParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.junit.jupiter.api.Test;

class CryptoCapabilitiesTest
{
	@Test
	void allPrimitivesPassTheirKnownAnswerTests()
	{
		List<CryptoCapabilities.Capability> caps = CryptoCapabilities.check();
		String failures = caps.stream().filter(c -> !c.available()).map(c -> c.name() + ": " + c.detail())
				.collect(Collectors.joining("; "));
		assertTrue(CryptoCapabilities.allAvailable(caps), failures);
		SelfTest.require();
	}

	@Test
	void postQuantumPrimitivesAreReported()
	{
		List<String> pq = CryptoCapabilities.check().stream().filter(CryptoCapabilities.Capability::postQuantum)
				.map(CryptoCapabilities.Capability::name).toList();
		assertEquals(List.of("ML-KEM-768", "ML-KEM-1024", "Hybrid KEM"), pq);
	}

	/** Only ML-KEM may come from a third-party library; everything that sees passwords or master keys is JDK or YaCT. */
	@Test
	void onlyMlKemUsesThirdPartyCode()
	{
		for (CryptoCapabilities.Capability c : CryptoCapabilities.check())
			if (c.detail().contains("BouncyCastle"))
				assertTrue(c.name().startsWith("ML-KEM"), c.name() + " uses BouncyCastle");
	}

	// ------------------------------------------------------------ independent implementations

	@Test
	void hkdfMatchesIndependentImplementation()
	{
		Random rnd = new Random(3);
		for (int i = 0; i < 200; i++)
		{
			byte[] ikm = bytes(rnd, 1 + rnd.nextInt(80));
			byte[] salt = rnd.nextBoolean() ? null : bytes(rnd, 1 + rnd.nextInt(40));
			byte[] ctx = bytes(rnd, rnd.nextInt(30));
			String label = "label-" + i;

			byte[] info = new byte[2 + label.length() + 2 + ctx.length];
			info[0] = 0;
			info[1] = (byte) label.length();
			System.arraycopy(label.getBytes(), 0, info, 2, label.length());
			info[2 + label.length()] = (byte) (ctx.length >>> 8);
			info[3 + label.length()] = (byte) ctx.length;
			System.arraycopy(ctx, 0, info, 4 + label.length(), ctx.length);

			HKDFBytesGenerator bc = new HKDFBytesGenerator(new SHA3Digest(256));
			bc.init(new HKDFParameters(ikm, salt, info));
			byte[] expected = new byte[32];
			bc.generateBytes(expected, 0, 32);
			assertArrayEquals(expected, Kdf.hkdf(ikm, salt, label, ctx));
		}
	}

	@Test
	void hmacMatchesIndependentImplementation()
	{
		Random rnd = new Random(4);
		for (int i = 0; i < 100; i++)
		{
			byte[] key = bytes(rnd, 1 + rnd.nextInt(200));
			byte[] data = bytes(rnd, rnd.nextInt(500));
			HMac bc = new HMac(new SHA3Digest(256));
			bc.init(new KeyParameter(key));
			bc.update(data, 0, data.length);
			byte[] expected = new byte[32];
			bc.doFinal(expected, 0);
			assertArrayEquals(expected, Kdf.hmac(key, data, 0, data.length));
		}
	}

	// ------------------------------------------------------------ provider injection

	/** A provider merely named like the JDK's is not accepted as the JDK's. */
	@Test
	void fakeProvidersAreNotGenuine()
	{
		Provider fake = new Provider("SunJCE", "21", "imitation") { };
		assertFalse(JdkCrypto.isGenuine(fake, "com.sun.crypto.provider.SunJCE", Set.of("java.base")));
		assertTrue(JdkCrypto.isGenuine(Security.getProvider("SunJCE"), "com.sun.crypto.provider.SunJCE", Set.of("java.base")));
	}

	/**
	 * Code that registers its own AES-GCM in front of the JDK's (as a compromised
	 * dependency could) must not receive YaCT's keys.
	 */
	@Test
	void injectedProviderIsIgnored() throws Exception
	{
		Provider evil = new Provider("Evil", "1", "steals keys")
		{
			{
				put("Cipher.AES/GCM/NoPadding", StealingCipher.class.getName());
				put("Cipher.ChaCha20-Poly1305", StealingCipher.class.getName());
				put("Mac.HmacSHA3-256", StealingCipher.class.getName());
			}
		};
		Security.insertProviderAt(evil, 1);
		try
		{
			assertEquals("Evil", javax.crypto.Cipher.getInstance("AES/GCM/NoPadding").getProvider().getName(),
					"the name lookup is hijacked");
			StealingCipher.used = false; // from here on, only YaCT's own calls count
			assertEquals("SunJCE (JDK)", CipherSuite.AES_256_GCM.implementation());
			assertEquals("SunJCE (JDK)", CipherSuite.CHACHA20_POLY1305.implementation());
			assertEquals("SunJCE", JdkCrypto.hmacSha3_256().getProvider().getName());
			assertTrue(CryptoCapabilities.allAvailable(CryptoCapabilities.check()));
			assertFalse(StealingCipher.used, "the injected cipher was used");
		}
		finally
		{
			Security.removeProvider("Evil");
		}
	}

	public static final class StealingCipher extends CipherSpi
	{
		static volatile boolean used;

		public StealingCipher()
		{
			used = true;
		}

		@Override protected void engineSetMode(String mode) { }
		@Override protected void engineSetPadding(String padding) { }
		@Override protected int engineGetBlockSize() { return 16; }
		@Override protected int engineGetOutputSize(int inputLen) { return inputLen; }
		@Override protected byte[] engineGetIV() { return null; }
		@Override protected java.security.AlgorithmParameters engineGetParameters() { return null; }
		@Override protected void engineInit(int opmode, java.security.Key key, java.security.SecureRandom random) { }
		@Override protected void engineInit(int opmode, java.security.Key key, java.security.spec.AlgorithmParameterSpec params, java.security.SecureRandom random) { }
		@Override protected void engineInit(int opmode, java.security.Key key, java.security.AlgorithmParameters params, java.security.SecureRandom random) { }
		@Override protected byte[] engineUpdate(byte[] input, int inputOffset, int inputLen) { return new byte[0]; }
		@Override protected int engineUpdate(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) { return 0; }
		@Override protected byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen) { return new byte[0]; }
		@Override protected int engineDoFinal(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) { return 0; }
	}

	private static byte[] bytes(Random rnd, int n)
	{
		byte[] b = new byte[n];
		rnd.nextBytes(b);
		return b;
	}
}
