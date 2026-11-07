/*******************************************************************************
 * YaCT | (c) 2015-2026 Christian Hoppe | http://opensource.org/licenses/MIT
 ******************************************************************************/
package yact.ui;

import java.util.concurrent.CancellationException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.function.Consumer;

import javafx.animation.PauseTransition;
import javafx.beans.property.ReadOnlyBooleanProperty;
import javafx.beans.property.ReadOnlyBooleanWrapper;
import javafx.geometry.Insets;
import javafx.scene.Scene;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.control.ProgressBar;
import javafx.scene.layout.HBox;
import javafx.scene.layout.Priority;
import javafx.scene.layout.Region;
import javafx.scene.layout.VBox;
import javafx.stage.Modality;
import javafx.stage.Stage;
import javafx.stage.StageStyle;
import javafx.stage.Window;
import javafx.util.Duration;

/**
 * Runs jobs one at a time on a single background thread. A container is not
 * thread-safe, so every access to it goes through here; the UI thread never
 * touches it. Jobs that take longer than a moment show a modal progress window.
 */
final class Worker
{
	private final ExecutorService executor = Executors.newSingleThreadExecutor(r -> {
		Thread t = new Thread(r, "yact-worker");
		t.setDaemon(true);
		return t;
	});
	private final ReadOnlyBooleanWrapper busy = new ReadOnlyBooleanWrapper(false);
	private final Window owner;

	Worker(Window owner)
	{
		this.owner = owner;
	}

	ReadOnlyBooleanProperty busyProperty()
	{
		return busy.getReadOnlyProperty();
	}

	/** Runs {@code job}; errors are shown to the user, cancellation is silent. */
	<T> void submit(Job<T> job, Consumer<T> onSuccess)
	{
		submit(job, onSuccess, e -> ErrorMessages.show(owner, e));
	}

	<T> void submit(Job<T> job, Consumer<T> onSuccess, Consumer<Throwable> onFailure)
	{
		if (busy.get())
			throw new IllegalStateException("another job is running");
		busy.set(true);
		Stage progress = progressWindow(job);
		PauseTransition delay = new PauseTransition(Duration.millis(300));
		delay.setOnFinished(e -> {
			if (job.isRunning())
				progress.show();
		});
		delay.play();

		job.setOnSucceeded(e -> {
			delay.stop();
			progress.close();
			busy.set(false);
			onSuccess.accept(job.getValue());
		});
		job.setOnFailed(e -> {
			delay.stop();
			progress.close();
			busy.set(false);
			Throwable ex = job.getException();
			if (!(ex instanceof CancellationException))
				onFailure.accept(ex);
		});
		executor.execute(job);
	}

	private Stage progressWindow(Job<?> job)
	{
		Stage stage = new Stage(StageStyle.UTILITY);
		stage.initOwner(owner);
		stage.initModality(Modality.WINDOW_MODAL);
		stage.titleProperty().bind(job.titleProperty());
		stage.setOnCloseRequest(e -> e.consume()); // the job decides when it is done

		Label message = new Label();
		message.textProperty().bind(job.messageProperty());
		message.setWrapText(true);
		ProgressBar bar = new ProgressBar();
		bar.progressProperty().bind(job.progressProperty());
		bar.setMaxWidth(Double.MAX_VALUE);

		HBox buttons = new HBox();
		Region spacer = new Region();
		HBox.setHgrow(spacer, Priority.ALWAYS);
		buttons.getChildren().add(spacer);
		if (job.isCancellable())
		{
			Button cancel = new Button(Messages.get("button.cancel"));
			cancel.setOnAction(e -> {
				cancel.setDisable(true);
				job.requestCancel();
			});
			buttons.getChildren().add(cancel);
		}

		VBox box = new VBox(12, message, bar, buttons);
		box.setPadding(new Insets(16));
		box.setPrefWidth(420);
		stage.setScene(new Scene(box));
		stage.setResizable(false);
		return stage;
	}

	void shutdown()
	{
		executor.shutdown();
	}
}
