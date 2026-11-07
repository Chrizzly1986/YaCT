/*******************************************************************************
 * YaCT | (c) 2015-2026 Christian Hoppe | http://opensource.org/licenses/MIT
 ******************************************************************************/
package yact.ui;

import java.io.UncheckedIOException;
import java.nio.file.AccessDeniedException;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.NoSuchFileException;

import javafx.scene.control.Alert;
import javafx.scene.control.Alert.AlertType;
import javafx.scene.control.TextArea;
import javafx.stage.Window;
import yact.core.codec.FormatException;
import yact.core.container.ContainerFullException;
import yact.core.format.ContainerFormatException;
import yact.core.format.IntegrityException;
import yact.core.format.InvalidCredentialsException;

/** Turns exceptions into messages a user can act on. */
final class ErrorMessages
{
	private ErrorMessages()
	{
	}

	static String describe(Throwable e)
	{
		while ((e instanceof UncheckedIOException || e instanceof java.util.concurrent.ExecutionException)
				&& e.getCause() != null)
			e = e.getCause();
		if (e instanceof InvalidCredentialsException)
			return Messages.get("error.credentials");
		if (e instanceof IntegrityException)
			return Messages.get("error.integrity");
		if (e instanceof ContainerFormatException)
			return Messages.get("error.notContainer");
		if (e instanceof FormatException)
			return Messages.get("error.badFile", e.getMessage());
		if (e instanceof ContainerFullException)
			return Messages.get("error.full");
		if (e instanceof FileAlreadyExistsException f)
			return Messages.get("error.exists", f.getFile());
		if (e instanceof NoSuchFileException f)
			return Messages.get("error.missing", f.getFile());
		if (e instanceof AccessDeniedException f)
			return Messages.get("error.access", f.getFile());
		if ("container is already open".equals(e.getMessage()))
			return Messages.get("error.inUse");
		String detail = e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName();
		return Messages.get("error.general", detail);
	}

	static void show(Window owner, Throwable e)
	{
		Alert alert = new Alert(AlertType.ERROR, describe(e));
		alert.initOwner(owner);
		alert.setHeaderText(null);
		alert.setTitle(Messages.get("app.name"));
		if (!(e instanceof InvalidCredentialsException) && !(e instanceof ContainerFullException))
		{
			// Details for bug reports, collapsed by default.
			java.io.StringWriter sw = new java.io.StringWriter();
			e.printStackTrace(new java.io.PrintWriter(sw));
			TextArea details = new TextArea(sw.toString());
			details.setEditable(false);
			details.setPrefRowCount(10);
			alert.getDialogPane().setExpandableContent(details);
		}
		alert.showAndWait();
	}
}
