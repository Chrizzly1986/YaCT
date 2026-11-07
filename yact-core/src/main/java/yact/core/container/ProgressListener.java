/*******************************************************************************
 * YaCT | (c) 2015-2026 Christian Hoppe | http://opensource.org/licenses/MIT
 ******************************************************************************/
package yact.core.container;

/** Receives progress of long operations such as creating, growing or wiping. Called on the working thread. */
@FunctionalInterface
public interface ProgressListener
{
	ProgressListener NONE = (done, total) -> {
	};

	void progress(long done, long total);
}
