/*******************************************************************************
 * YaCT | (c) 2015-2026 Christian Hoppe | http://opensource.org/licenses/MIT
 ******************************************************************************/
package yact.core.crypto;

/**
 * The key derivation needs more memory than the Java heap can provide. Thrown
 * before the memory is allocated, so the application keeps running.
 */
public class InsufficientMemoryException extends RuntimeException
{
	private static final long serialVersionUID = 1L;

	private final long needed;

	public InsufficientMemoryException(long needed, long available)
	{
		super("key derivation needs " + (needed >> 20) + " MiB of memory, only " + (available >> 20) + " MiB available");
		this.needed = needed;
	}

	/** Bytes the operation would have needed. */
	public long needed()
	{
		return needed;
	}
}
