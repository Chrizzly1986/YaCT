/*******************************************************************************
 * YaCT | (c) 2015-2026 Christian Hoppe | http://opensource.org/licenses/MIT
 ******************************************************************************/
package yact.core.crypto;

/**
 * Cost parameters for Argon2id.
 *
 * <p>The limits checked here are hard limits. Argon2 parameters are read from
 * a container header before anything in it can be authenticated, so a
 * manipulated file must not be able to make YaCT allocate unbounded memory or
 * compute for hours. In addition, {@link Kdf#argon2id} refuses parameters that
 * need more memory than the Java heap has left, instead of crashing.
 *
 * @param memoryKiB   memory cost in KiB
 * @param iterations  number of passes
 * @param parallelism number of lanes
 */
public record Argon2Params(int memoryKiB, int iterations, int parallelism)
{
	/** 128 MiB, 3 passes, 4 lanes: twice the memory of RFC 9106's second recommended option. */
	public static final Argon2Params DEFAULT = new Argon2Params(128 * 1024, 3, 4);

	/** 512 MiB, 4 passes, 4 lanes, for users who accept an unlock of a few seconds. */
	public static final Argon2Params STRONG = new Argon2Params(512 * 1024, 4, 4);

	public static final int MAX_MEMORY_KIB = 1024 * 1024; // 1 GiB
	public static final int MAX_ITERATIONS = 10;
	public static final int MAX_PARALLELISM = 16;

	/** OWASP's minimum for Argon2id: 19 MiB, 2 passes. */
	private static final int RECOMMENDED_MIN_MEMORY_KIB = 19 * 1024;
	private static final int RECOMMENDED_MIN_ITERATIONS = 2;

	public Argon2Params
	{
		if (parallelism < 1 || parallelism > MAX_PARALLELISM)
			throw new IllegalArgumentException("parallelism must be 1.." + MAX_PARALLELISM);
		if (iterations < 1 || iterations > MAX_ITERATIONS)
			throw new IllegalArgumentException("iterations must be 1.." + MAX_ITERATIONS);
		// Argon2 itself requires at least 8 KiB per lane.
		if (memoryKiB < 8 * parallelism || memoryKiB > MAX_MEMORY_KIB)
			throw new IllegalArgumentException("memory must be " + (8 * parallelism) + ".." + MAX_MEMORY_KIB + " KiB");
	}

	/** True if these parameters are too weak to protect a password; only acceptable in tests. */
	public boolean isBelowRecommended()
	{
		return memoryKiB < RECOMMENDED_MIN_MEMORY_KIB || iterations < RECOMMENDED_MIN_ITERATIONS;
	}

	/** Bytes of memory the computation needs. */
	public long memoryBytes()
	{
		return memoryKiB * 1024L;
	}
}
