/*******************************************************************************
 * YaCT | (c) 2015-2026 Christian Hoppe | http://opensource.org/licenses/MIT
 ******************************************************************************/
package yact.core.container;

/**
 * Receives progress of long operations such as creating, growing, wiping,
 * importing or extracting. Called on the working thread.
 *
 * <p>A listener may throw an unchecked exception (e.g.
 * {@link java.util.concurrent.CancellationException}) to cancel. The
 * operation then stops as if it had failed: creating removes the new file,
 * growing leaves the container valid at a size between the old and the new
 * one, imports leave the container unchanged.
 */
@FunctionalInterface
public interface ProgressListener
{
	ProgressListener NONE = (done, total) -> {
	};

	void progress(long done, long total);
}
