/*******************************************************************************
 * YaCT | (c) 2015-2026 Christian Hoppe | http://opensource.org/licenses/MIT
 ******************************************************************************/
package yact.core.crypto;

import java.security.DrbgParameters;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Set;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;

/**
 * Access to the JDK's own cryptography, and only to it.
 *
 * <p>Code on the class path or in another module can register a JCA provider
 * under any name, also in front of the JDK's, or remove the JDK's providers.
 * {@code Cipher.getInstance("AES/GCM/NoPadding")} would then hand our keys to
 * that code. Therefore providers are never looked up by name alone: each one
 * must be a class of the expected module, loaded by the boot or platform class
 * loader, i.e. part of the Java runtime image itself. Such a class cannot be
 * planted without modifying the runtime installation.
 *
 * <p>The providers are resolved once, when this class is first used, and kept.
 * Later changes to the global provider list have no effect on YaCT.
 */
public final class JdkCrypto
{
	private static final Provider SUN = verified("SUN", "sun.security.provider.Sun", "java.base");
	private static final Provider SUN_JCE = verified("SunJCE", "com.sun.crypto.provider.SunJCE", "java.base");
	/** XDH (X25519) lives in jdk.crypto.ec up to JDK 21 and in java.base from JDK 22 on. */
	private static final Provider SUN_EC = verified("SunEC", "sun.security.ec.SunEC", "jdk.crypto.ec", "java.base");

	/** 256-bit Hash_DRBG from the SUN provider, seeded by the operating system. Thread-safe. */
	private static final SecureRandom RANDOM = newRandom();

	private JdkCrypto()
	{
	}

	/** Verifies that the JDK providers are available and genuine; throws otherwise. */
	public static void verify()
	{
		// Class initialisation has done the work; this only makes sure it ran.
		if (SUN == null || SUN_JCE == null || SUN_EC == null || RANDOM == null)
			throw new IllegalStateException("JDK cryptography unavailable");
	}

	/** The random number generator for all keys, salts and nonces. */
	public static SecureRandom random()
	{
		return RANDOM;
	}

	public static byte[] randomBytes(int n)
	{
		byte[] b = new byte[n];
		RANDOM.nextBytes(b);
		return b;
	}

	public static Cipher cipher(String transformation)
	{
		try
		{
			return Cipher.getInstance(transformation, SUN_JCE);
		}
		catch (GeneralSecurityException e)
		{
			throw new IllegalStateException(transformation + " not available", e);
		}
	}

	public static Mac hmacSha3_256()
	{
		try
		{
			return Mac.getInstance("HmacSHA3-256", SUN_JCE);
		}
		catch (GeneralSecurityException e)
		{
			throw new IllegalStateException("HmacSHA3-256 not available", e);
		}
	}

	public static MessageDigest sha3_256()
	{
		try
		{
			return MessageDigest.getInstance("SHA3-256", SUN);
		}
		catch (GeneralSecurityException e)
		{
			throw new IllegalStateException("SHA3-256 not available", e);
		}
	}

	public static KeyAgreement x25519Agreement()
	{
		try
		{
			return KeyAgreement.getInstance("X25519", SUN_EC);
		}
		catch (GeneralSecurityException e)
		{
			throw new IllegalStateException("X25519 not available", e);
		}
	}

	public static KeyFactory x25519KeyFactory()
	{
		try
		{
			return KeyFactory.getInstance("X25519", SUN_EC);
		}
		catch (GeneralSecurityException e)
		{
			throw new IllegalStateException("X25519 not available", e);
		}
	}

	/** Name and origin of the providers in use, for the self-test report. */
	public static String describe()
	{
		return SUN.getName() + ", " + SUN_JCE.getName() + ", " + SUN_EC.getName() + " (Java " + Runtime.version() + ")";
	}

	// ------------------------------------------------------------------ verification

	private static Provider verified(String name, String className, String... modules)
	{
		Provider p = Security.getProvider(name);
		if (p == null)
			throw new IllegalStateException("JDK provider " + name + " is missing");
		if (!isGenuine(p, className, Set.of(modules)))
			throw new IllegalStateException("JDK provider " + name + " has been replaced by " + p.getClass().getName()
					+ " from " + p.getClass().getModule());
		return p;
	}

	/**
	 * True if {@code p} is an instance of exactly {@code className}, defined in one of
	 * {@code modules} of the boot layer by the boot or platform class loader.
	 */
	static boolean isGenuine(Provider p, String className, Set<String> modules)
	{
		Class<?> c = p.getClass();
		Module m = c.getModule();
		ClassLoader loader = c.getClassLoader();
		return c.getName().equals(className)
				&& m.isNamed() && modules.contains(m.getName())
				&& m.getLayer() == ModuleLayer.boot()
				&& (loader == null || loader == ClassLoader.getPlatformClassLoader());
	}

	private static SecureRandom newRandom()
	{
		try
		{
			return SecureRandom.getInstance("DRBG",
					DrbgParameters.instantiation(256, DrbgParameters.Capability.RESEED_ONLY, "YaCT".getBytes()), SUN);
		}
		catch (GeneralSecurityException e)
		{
			throw new IllegalStateException("DRBG not available", e);
		}
	}
}
