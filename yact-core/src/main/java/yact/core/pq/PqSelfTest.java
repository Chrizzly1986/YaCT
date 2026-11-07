/*******************************************************************************
 * YaCT | (c) 2015-2026 Christian Hoppe | http://opensource.org/licenses/MIT
 ******************************************************************************/
package yact.core.pq;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.Map;

import yact.core.crypto.JdkCrypto;

/**
 * Known-answer tests for the post-quantum and X25519 parts, run by
 * {@link yact.core.crypto.CryptoCapabilities}. Each method returns a short
 * description or throws {@link IllegalStateException}.
 */
public final class PqSelfTest
{
	private static final HexFormat HEX = HexFormat.of();

	private PqSelfTest()
	{
	}

	/** RFC 7748, section 6.1: public key derivation, shared secret, rejection of a small-order point. */
	public static String x25519()
	{
		byte[] alice = HEX.parseHex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
		byte[] bobPublic = HEX.parseHex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
		check(Arrays.equals(X25519.publicKey(alice),
				HEX.parseHex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")), "public key");
		try
		{
			check(Arrays.equals(X25519.agree(alice, bobPublic),
					HEX.parseHex("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")), "shared secret");
		}
		catch (InvalidKeyException e)
		{
			throw new IllegalStateException("valid key rejected", e);
		}
		boolean rejected;
		try
		{
			X25519.agree(alice, new byte[32]);
			rejected = false;
		}
		catch (InvalidKeyException e)
		{
			rejected = true;
		}
		check(rejected, "small-order point accepted");
		return "RFC 7748 vectors, " + JdkCrypto.x25519Agreement().getProvider().getName() + " (JDK)";
	}

	/**
	 * NIST ACVP vectors: key generation for both parameter sets (hashes of the
	 * expected keys), encapsulation for ML-KEM-1024; then decapsulation and
	 * implicit rejection.
	 */
	public static String mlKem(HybridKem kem)
	{
		byte[] seed;
		String ekHash;
		String dkHash;
		if (kem == HybridKem.MLKEM768_X25519)
		{
			seed = HEX.parseHex("E582B7D75E6C80B05AE392A1FC9F7153B12390FD99930368CC67A768BAEBC8A0"
					+ "1CDACB8740C0B87C4A379575F187B367CBFA3B300BF591B109F79816E9CBE8F0");
			ekHash = "81e66ef5a7a221619f6a64039cc369843e10df5c859f6959cc3fd8e5272330fd";
			dkHash = "be81068c104cd6cf8efd800b294f4a15bb8a8050993fd54a2cc428841ef6ca44";
		}
		else
		{
			seed = HEX.parseHex("F3A706FAF090C03DB506863AB0B20BD8A1627956318E88C67EB875E8E7266009"
					+ "35D2BC43DD1CC879F765BF2A0C5E297889DDE910E57E2BB0EAE417B90AB7A275");
			ekHash = "9370fe5b05ddc92c939f62cbde4c0fea36f45cd20c5748cf3ac891a4c2604496";
			dkHash = "b8c683c71564ff8e2391c57b68c3a1ff186734b13e31d2a075b65307c8b80888";
		}
		byte[] ek = MlKem.publicKey(kem, seed);
		check(sha3(ek).equals(ekHash), "key generation (encapsulation key)");
		check(sha3(MlKem.expandedDecapsulationKey(kem, seed)).equals(dkHash), "key generation (decapsulation key)");

		if (kem == HybridKem.MLKEM1024_X25519)
		{
			Map<String, String> v = vector("mlkem1024-encap-kat.txt");
			MlKem.Encapsulated e = MlKem.encapsulate(kem, HEX.parseHex(v.get("ek")), HEX.parseHex(v.get("m")));
			check(Arrays.equals(e.ciphertext(), HEX.parseHex(v.get("c"))), "encapsulation (ciphertext)");
			check(Arrays.equals(e.secret(), HEX.parseHex(v.get("k"))), "encapsulation (shared secret)");
		}

		MlKem.Encapsulated own = MlKem.encapsulate(kem, ek);
		check(Arrays.equals(own.secret(), MlKem.decapsulate(kem, seed, own.ciphertext())), "decapsulation");
		byte[] tampered = own.ciphertext().clone();
		tampered[7] ^= 1;
		check(!Arrays.equals(own.secret(), MlKem.decapsulate(kem, seed, tampered)), "implicit rejection");
		return "NIST ACVP vectors, BouncyCastle";
	}

	/** A fresh hybrid key pair must encapsulate and decapsulate, and another key pair must not recover the key. */
	public static String hybrid()
	{
		HybridKem kem = HybridKem.DEFAULT;
		try (HybridKeyPair key = HybridKeyPair.generate(kem, JdkCrypto.random());
				HybridKeyPair other = HybridKeyPair.generate(kem, JdkCrypto.random()))
		{
			byte[] context = JdkCrypto.randomBytes(16);
			Hybrid.Encapsulation enc = Hybrid.encapsulate(key.publicKey(), context, null);
			check(Arrays.equals(enc.key(), Hybrid.decapsulate(key, enc.x25519Ephemeral(), enc.mlKemCiphertext(), context)),
					"round trip");
			check(!Arrays.equals(enc.key(), Hybrid.decapsulate(other, enc.x25519Ephemeral(), enc.mlKemCiphertext(), context)),
					"another key pair recovered the key");
		}
		return kem.displayName() + ", HKDF-SHA3-256 combiner";
	}

	private static Map<String, String> vector(String resource)
	{
		Map<String, String> v = new HashMap<>();
		try (InputStream in = PqSelfTest.class.getResourceAsStream(resource))
		{
			if (in == null)
				throw new IllegalStateException("test vector " + resource + " missing");
			try (BufferedReader r = new BufferedReader(new InputStreamReader(in, StandardCharsets.US_ASCII)))
			{
				for (String line; (line = r.readLine()) != null;)
				{
					int eq = line.indexOf(" = ");
					if (!line.startsWith("#") && eq > 0)
						v.put(line.substring(0, eq), line.substring(eq + 3));
				}
			}
		}
		catch (IOException e)
		{
			throw new IllegalStateException("cannot read test vector " + resource, e);
		}
		return v;
	}

	private static String sha3(byte[] data)
	{
		return HEX.formatHex(JdkCrypto.sha3_256().digest(data));
	}

	private static void check(boolean ok, String what)
	{
		if (!ok)
			throw new IllegalStateException(what + " does not match the known answer");
	}
}
