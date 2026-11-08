/*******************************************************************************
 * YaCT | (c) 2015-2026 Christian Hoppe | http://opensource.org/licenses/MIT
 ******************************************************************************/
package yact.core.container;

import java.util.List;

/**
 * Result of {@link Container#verify(ProgressListener)}.
 *
 * @param files           number of files read
 * @param bytes           their total size
 * @param damaged         paths of files whose content failed authentication or has the wrong size
 * @param headerIntact    both header copies on disk equal the header in use
 * @param stateIntact     the superblock and index on disk are exactly the state in use; {@code false}
 *                        means the file was changed by something else while it was open
 * @param olderStateWiped an older state that could still be decrypted was found and has been overwritten
 */
public record VerificationReport(int files, long bytes, List<String> damaged, boolean headerIntact,
		boolean stateIntact, boolean olderStateWiped)
{
	public VerificationReport
	{
		damaged = List.copyOf(damaged);
	}

	/** True if nothing was damaged or changed from outside. */
	public boolean intact()
	{
		return damaged.isEmpty() && headerIntact && stateIntact;
	}
}
