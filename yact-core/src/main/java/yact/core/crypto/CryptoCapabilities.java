/*******************************************************************************
 * YaCT | (c) 2015-2026 Christian Hoppe | http://opensource.org/licenses/MIT
 ******************************************************************************/
package yact.core.crypto;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.function.Supplier;

import javax.crypto.AEADBadTagException;

import yact.core.pq.HybridKem;
import yact.core.pq.PqSelfTest;

/**
 * Known-answer self-test of every cryptographic primitive YaCT uses.
 *
 * <p>Each primitive must reproduce published test vectors (NIST, RFC) or, for
 * HKDF-SHA3-256 which has none, a value computed with an independent
 * implementation. A round trip alone would not notice an implementation that
 * was tampered with, e.g. one that ignores its key; a known answer does.
 * {@link SelfTest#require()} runs this before any container is created or
 * opened.
 */
public final class CryptoCapabilities
{
	/** Result of a single self-test. */
	public record Capability(String name, String purpose, boolean postQuantum, boolean available, String detail)
	{
	}

	private static final HexFormat HEX = HexFormat.of();

	private CryptoCapabilities()
	{
	}

	/** Runs all self-tests and returns one entry per primitive, in a fixed order. */
	public static List<Capability> check()
	{
		List<Capability> result = new ArrayList<>();
		result.add(run("Random generator", "Keys, salts, nonces", false, CryptoCapabilities::random));
		result.add(run("AES-256-GCM", "Data encryption (default)", false, CryptoCapabilities::aesGcm));
		result.add(run("ChaCha20-Poly1305", "Data encryption (alternative)", false, CryptoCapabilities::chaCha));
		result.add(run("SHA3-256", "Fingerprints", false, CryptoCapabilities::sha3));
		result.add(run("HKDF-SHA3-256", "Key derivation, header MAC", false, CryptoCapabilities::hkdf));
		result.add(run("BLAKE2b", "Inside Argon2id", false, CryptoCapabilities::blake2b));
		result.add(run("Argon2id", "Password-based key derivation", false, CryptoCapabilities::argon2id));
		result.add(run("X25519", "Classical half of key entries", false, PqSelfTest::x25519));
		result.add(run("ML-KEM-768", "PQ key encapsulation (FIPS 203)", true, () -> PqSelfTest.mlKem(HybridKem.MLKEM768_X25519)));
		result.add(run("ML-KEM-1024", "PQ key encapsulation (FIPS 203)", true, () -> PqSelfTest.mlKem(HybridKem.MLKEM1024_X25519)));
		result.add(run("Hybrid KEM", "PQ key entries: ML-KEM + X25519", true, PqSelfTest::hybrid));
		return result;
	}

	/** True if every primitive passed its self-test. */
	public static boolean allAvailable(List<Capability> capabilities)
	{
		return capabilities.stream().allMatch(Capability::available);
	}

	private static Capability run(String name, String purpose, boolean pq, Supplier<String> test)
	{
		try
		{
			return new Capability(name, purpose, pq, true, test.get());
		}
		catch (RuntimeException | LinkageError e)
		{
			return new Capability(name, purpose, pq, false, e.getClass().getSimpleName() + ": " + e.getMessage());
		}
	}

	// ---------------------------------------------------------------- tests

	private static String random()
	{
		JdkCrypto.verify();
		byte[] a = JdkCrypto.randomBytes(32);
		byte[] b = JdkCrypto.randomBytes(32);
		check(!Arrays.equals(a, b) && !Arrays.equals(a, new byte[32]), "random output repeats");
		return "DRBG (Hash_DRBG, 256 bit); providers: " + JdkCrypto.describe();
	}

	/** McGrew/Viega GCM specification, test case 16 (AES-256, 60-byte plaintext, 20-byte AAD). */
	private static String aesGcm()
	{
		return aead(CipherSuite.AES_256_GCM,
				"feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308",
				"cafebabefacedbaddecaf888",
				"feedfacedeadbeeffeedfacedeadbeefabaddad2",
				"d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
				"522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662"
						+ "76fc6ece0f4e1768cddf8853bb2d551b");
	}

	/** RFC 8439, section 2.8.2. */
	private static String chaCha()
	{
		return aead(CipherSuite.CHACHA20_POLY1305,
				"808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
				"070000004041424344454647",
				"50515253c0c1c2c3c4c5c6c7",
				HEX.formatHex(("Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, "
						+ "sunscreen would be it.").getBytes(StandardCharsets.US_ASCII)),
				"d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116"
						+ "1ae10b594f09e26a7e902ecbd0600691");
	}

	private static String aead(CipherSuite suite, String key, String nonce, String aad, String plain, String sealed)
	{
		byte[] k = HEX.parseHex(key);
		byte[] n = HEX.parseHex(nonce);
		byte[] a = HEX.parseHex(aad);
		byte[] expected = HEX.parseHex(sealed);
		check(Arrays.equals(suite.seal(k, n, a, HEX.parseHex(plain)), expected), "encryption");
		try
		{
			check(Arrays.equals(suite.open(k, n, a, expected), HEX.parseHex(plain)), "decryption");
		}
		catch (AEADBadTagException e)
		{
			throw new IllegalStateException("valid ciphertext rejected", e);
		}
		expected[expected.length / 2] ^= 1;
		boolean rejected;
		try
		{
			suite.open(k, n, a, expected);
			rejected = false;
		}
		catch (AEADBadTagException e)
		{
			rejected = true;
		}
		check(rejected, "tampered ciphertext accepted");
		return "test vector, " + suite.implementation();
	}

	/** FIPS 202 example: SHA3-256("abc"). */
	private static String sha3()
	{
		check(HEX.formatHex(JdkCrypto.sha3_256().digest("abc".getBytes(StandardCharsets.US_ASCII)))
				.equals("3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"), "SHA3-256");
		return "FIPS 202 example, " + JdkCrypto.sha3_256().getProvider().getName() + " (JDK)";
	}

	/** Value computed with Python's hashlib/hmac, independent of Java and BouncyCastle. */
	private static String hkdf()
	{
		byte[] ikm = new byte[22];
		Arrays.fill(ikm, (byte) 0x0b);
		byte[] salt = new byte[13];
		for (int i = 0; i < salt.length; i++)
			salt[i] = (byte) i;
		check(HEX.formatHex(Kdf.hkdf(ikm, salt, "YaCT self-test", new byte[] { 1, 2, 3 }))
				.equals("9ac13352094187a7d814e4c6fbb834be09e01af34868702953fece4206eb5312"), "HKDF-SHA3-256");
		return "independent reference value, HMAC from " + JdkCrypto.hmacSha3_256().getProvider().getName() + " (JDK)";
	}

	/** RFC 7693, appendix A. */
	private static String blake2b()
	{
		check(HEX.formatHex(Blake2b.hash(64, "abc".getBytes(StandardCharsets.US_ASCII))).equals(
				"ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923"),
				"BLAKE2b-512");
		return "RFC 7693 vector, YaCT implementation";
	}

	/** RFC 9106, section 5.3. */
	private static String argon2id()
	{
		byte[] tag = Argon2id.hash(fill(32, 1), fill(16, 2), fill(8, 3), fill(12, 4), 32, 3, 4, 32);
		check(HEX.formatHex(tag).equals("0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659"), "Argon2id");
		return "RFC 9106 vector, YaCT implementation";
	}

	private static byte[] fill(int n, int v)
	{
		byte[] b = new byte[n];
		Arrays.fill(b, (byte) v);
		return b;
	}

	private static void check(boolean ok, String what)
	{
		if (!ok)
			throw new IllegalStateException(what + " does not match the known answer");
	}

	/** Prints the report; exit code 1 if any primitive fails. */
	public static void main(String[] args)
	{
		List<Capability> caps = check();
		System.out.println("YaCT crypto self-test (Java " + Runtime.version() + ")");
		for (Capability c : caps)
			System.out.printf("  [%s] %-18s %-5s %s%n", c.available() ? " OK " : "FAIL", c.name(), c.postQuantum() ? "PQ" : "",
					c.detail());
		System.exit(allAvailable(caps) ? 0 : 1);
	}
}
