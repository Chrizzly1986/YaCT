/*******************************************************************************
 * YaCT | (c) 2015-2026 Christian Hoppe | http://opensource.org/licenses/MIT
 ******************************************************************************/
package yact.core.crypto;

import java.util.List;
import java.util.stream.Collectors;

/**
 * Gate in front of every container operation: the known-answer self-test
 * ({@link CryptoCapabilities}) must have passed in this process. A runtime
 * whose cryptography was tampered with, or simply broken, therefore cannot
 * create or open containers; it cannot produce containers that others could
 * open without the credentials.
 */
public final class SelfTest
{
	private static volatile boolean passed;

	private SelfTest()
	{
	}

	/**
	 * Runs the self-test once per process; afterwards returns immediately.
	 *
	 * @throws SelfTestFailedException if any primitive fails
	 */
	public static void require()
	{
		if (passed)
			return;
		synchronized (SelfTest.class)
		{
			if (passed)
				return;
			List<CryptoCapabilities.Capability> caps = CryptoCapabilities.check();
			if (!CryptoCapabilities.allAvailable(caps))
				throw new SelfTestFailedException(caps.stream().filter(c -> !c.available())
						.map(c -> c.name() + ": " + c.detail()).collect(Collectors.joining("; ")));
			passed = true;
		}
	}

	/** The cryptographic self-test failed; YaCT refuses to work with containers. */
	public static final class SelfTestFailedException extends IllegalStateException
	{
		private static final long serialVersionUID = 1L;

		SelfTestFailedException(String failures)
		{
			super("cryptographic self-test failed: " + failures);
		}
	}
}
