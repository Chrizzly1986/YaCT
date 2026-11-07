/*******************************************************************************
 * YaCT | (c) 2015-2026 Christian Hoppe | http://opensource.org/licenses/MIT
 ******************************************************************************/
package yact.ui;

import java.util.concurrent.CancellationException;

import javafx.concurrent.Task;
import yact.core.container.ProgressListener;

/**
 * A background operation on the worker thread.
 *
 * <p>Cancelling never interrupts the thread: an interrupt would close the
 * container's file channel. Instead {@link #requestCancel()} sets a flag that
 * the job's progress listeners check, so the core stops at a safe point.
 */
final class Job<T> extends Task<T>
{
	@FunctionalInterface
	interface Body<T>
	{
		T run(Job<T> job) throws Exception;
	}

	private final Body<T> body;
	private final boolean cancellable;
	private volatile boolean cancelRequested;

	private Job(String title, boolean cancellable, Body<T> body)
	{
		this.body = body;
		this.cancellable = cancellable;
		updateTitle(title);
		updateMessage(title);
	}

	static <T> Job<T> of(String title, boolean cancellable, Body<T> body)
	{
		return new Job<>(title, cancellable, body);
	}

	boolean isCancellable()
	{
		return cancellable;
	}

	void requestCancel()
	{
		cancelRequested = true;
	}

	/** Throws {@link CancellationException} if cancelling was requested; call between steps. */
	void checkCancelled()
	{
		if (cancelRequested)
			throw new CancellationException();
	}

	void message(String text)
	{
		updateMessage(text);
	}

	/** Progress of one step that is part {@code [base, base + step total)} of {@code grandTotal}. */
	ProgressListener progress(long base, long grandTotal)
	{
		return (done, total) -> {
			checkCancelled();
			updateProgress(base + done, Math.max(1, grandTotal));
		};
	}

	/** Progress of a job that is a single step. */
	ProgressListener progress()
	{
		return (done, total) -> {
			checkCancelled();
			updateProgress(done, Math.max(1, total));
		};
	}

	@Override
	protected T call() throws Exception
	{
		return body.run(this);
	}
}
