/*******************************************************************************
 * YaCT | (c) 2015-2026 Christian Hoppe | http://opensource.org/licenses/MIT
 ******************************************************************************/
package yact.ui;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Optional;

import javafx.beans.binding.Bindings;
import javafx.beans.binding.BooleanBinding;
import javafx.geometry.Insets;
import javafx.scene.control.Alert;
import javafx.scene.control.Alert.AlertType;
import javafx.scene.control.Button;
import javafx.scene.control.ButtonBar.ButtonData;
import javafx.scene.control.ButtonType;
import javafx.scene.control.ChoiceBox;
import javafx.scene.control.Label;
import javafx.scene.control.PasswordField;
import javafx.scene.control.TextField;
import javafx.scene.layout.GridPane;
import javafx.scene.layout.HBox;
import javafx.scene.layout.Priority;
import javafx.stage.FileChooser;
import javafx.stage.Window;
import javafx.util.StringConverter;
import yact.core.crypto.Argon2Params;

/** Building blocks shared by the dialogs. */
final class Dialogs
{
	static final FileChooser.ExtensionFilter CONTAINERS = new FileChooser.ExtensionFilter(
			Messages.get("filter.containers"), "*.yact");
	static final FileChooser.ExtensionFilter PRIVATE_KEYS = new FileChooser.ExtensionFilter(
			Messages.get("filter.privateKeys"), "*.yactkey");
	static final FileChooser.ExtensionFilter PUBLIC_KEYS = new FileChooser.ExtensionFilter(
			Messages.get("filter.publicKeys"), "*.yactpub");
	static final FileChooser.ExtensionFilter ALL = new FileChooser.ExtensionFilter(Messages.get("filter.all"), "*");

	/**
	 * Our own OK and Cancel buttons. JavaFX's built-in ones are translated by
	 * JavaFX itself, which has no European Portuguese and would show English.
	 */
	static final ButtonType OK = new ButtonType(Messages.get("button.ok"), ButtonData.OK_DONE);
	static final ButtonType CANCEL = new ButtonType(Messages.get("button.cancel"), ButtonData.CANCEL_CLOSE);

	private Dialogs()
	{
	}

	/** An alert with our own buttons; with none given, a single OK. */
	static Alert alert(AlertType type, String text, ButtonType... buttons)
	{
		Alert a = new Alert(type, text, buttons.length == 0 ? new ButtonType[] { OK } : buttons);
		a.setTitle(Messages.get("app.name"));
		return a;
	}

	/**
	 * Keeps labels and buttons at their full text width; the window grows
	 * instead of truncating them to "…". Call once the content is complete.
	 */
	static void noTruncation(javafx.scene.Parent root)
	{
		for (javafx.scene.Node n : root.getChildrenUnmodifiable())
		{
			// Wrapping texts are meant to wrap; only single-line labels and buttons keep their width.
			if (n instanceof javafx.scene.control.Labeled l && !l.isWrapText())
				l.setMinWidth(javafx.scene.layout.Region.USE_PREF_SIZE);
			if (n instanceof javafx.scene.control.TitledPane t && t.getContent() instanceof javafx.scene.Parent c)
				noTruncation(c);
			if (n instanceof javafx.scene.control.ToolBar tb)
				tb.getItems().forEach(i -> {
					if (i instanceof javafx.scene.control.Labeled l)
						l.setMinWidth(javafx.scene.layout.Region.USE_PREF_SIZE);
				});
			if (n instanceof javafx.scene.Parent child)
				noTruncation(child);
		}
	}

	/** Applies {@link #noTruncation} to a dialog's content and button bar. */
	static void noTruncation(javafx.scene.control.Dialog<?> d)
	{
		noTruncation(d.getDialogPane());
	}

	static GridPane grid()
	{
		GridPane g = new GridPane();
		g.setHgap(10);
		g.setVgap(8);
		g.setPadding(new Insets(16));
		return g;
	}

	/** A text field for a path with a "Browse…" button next to it. */
	static HBox pathField(TextField field, Runnable browse)
	{
		Button b = new Button(Messages.get("button.browse"));
		b.setOnAction(e -> browse.run());
		HBox.setHgrow(field, Priority.ALWAYS);
		field.setPrefColumnCount(28);
		return new HBox(6, field, b);
	}

	static Optional<Path> save(Window owner, String title, String initialName, FileChooser.ExtensionFilter filter)
	{
		FileChooser fc = new FileChooser();
		fc.setTitle(title);
		fc.setInitialFileName(initialName);
		fc.getExtensionFilters().addAll(filter, ALL);
		File f = fc.showSaveDialog(owner);
		return Optional.ofNullable(f).map(File::toPath);
	}

	static Optional<Path> open(Window owner, String title, FileChooser.ExtensionFilter filter)
	{
		FileChooser fc = new FileChooser();
		fc.setTitle(title);
		fc.getExtensionFilters().addAll(filter, ALL);
		File f = fc.showOpenDialog(owner);
		return Optional.ofNullable(f).map(File::toPath);
	}

	/** Appends {@code extension} unless the name already has it. */
	static Path withExtension(Path p, String extension)
	{
		String name = p.getFileName().toString();
		return name.toLowerCase().endsWith(extension) ? p : p.resolveSibling(name + extension);
	}

	static boolean confirm(Window owner, String header, String text, String okLabel)
	{
		ButtonType ok = new ButtonType(okLabel, ButtonData.OK_DONE);
		Alert a = alert(AlertType.CONFIRMATION, text, ok, CANCEL);
		a.initOwner(owner);
		a.setTitle(Messages.get("app.name"));
		a.setHeaderText(header);
		a.getDialogPane().setPrefWidth(520);
		return a.showAndWait().filter(ok::equals).isPresent();
	}

	static void info(Window owner, String header, String text)
	{
		Alert a = alert(AlertType.INFORMATION, text);
		a.initOwner(owner);
		a.setTitle(Messages.get("app.name"));
		a.setHeaderText(header);
		a.getDialogPane().setPrefWidth(520);
		a.showAndWait();
	}

	enum Conflict
	{
		REPLACE, SKIP
	}

	/** Asks what to do with {@code count} existing files; empty means cancel. */
	static Optional<Conflict> conflict(Window owner, int count, String example)
	{
		ButtonType replace = new ButtonType(Messages.get("button.replace"), ButtonData.YES);
		ButtonType skip = new ButtonType(Messages.get("button.skip"), ButtonData.NO);
		Alert a = alert(AlertType.CONFIRMATION, Messages.get("conflict.text", count, example), replace, skip, CANCEL);
		a.initOwner(owner);
		a.setTitle(Messages.get("app.name"));
		a.setHeaderText(Messages.get("conflict.header"));
		Optional<ButtonType> r = a.showAndWait();
		if (r.isEmpty() || r.get() == CANCEL)
			return Optional.empty();
		return Optional.of(r.get() == replace ? Conflict.REPLACE : Conflict.SKIP);
	}

	/** Free space of the file system that would hold {@code file}, or -1 if unknown. */
	static long usableSpace(Path file)
	{
		try
		{
			Path dir = file.toAbsolutePath().getParent();
			while (dir != null && !Files.exists(dir))
				dir = dir.getParent();
			return dir == null ? -1 : Files.getFileStore(dir).getUsableSpace();
		}
		catch (Exception e)
		{
			return -1;
		}
	}

	// ------------------------------------------------------------------ passwords

	/** Two password fields with a strength rating; valid when both match and the password is long enough. */
	static final class PasswordPair
	{
		final PasswordField first = new PasswordField();
		final PasswordField second = new PasswordField();
		final Label rating = new Label();
		final BooleanBinding valid;

		PasswordPair()
		{
			rating.textProperty().bind(Bindings.createStringBinding(
					() -> first.getText().isEmpty() ? "" : Messages.get("password." + PasswordRating.of(first.getText()).name()),
					first.textProperty()));
			rating.getStyleClass().add("hint");
			valid = Bindings.createBooleanBinding(
					() -> PasswordRating.of(first.getText()).acceptable() && first.getText().equals(second.getText()),
					first.textProperty(), second.textProperty());
		}

		/** Adds the rows "Password", "Repeat" and the rating to {@code grid}, starting at {@code row}. */
		int addTo(GridPane grid, int row)
		{
			grid.addRow(row++, new Label(Messages.get("label.password")), first);
			grid.addRow(row++, new Label(Messages.get("label.passwordRepeat")), second);
			grid.add(rating, 1, row++);
			return row;
		}

		/** Problem to show, or null. */
		String problem()
		{
			if (!PasswordRating.of(first.getText()).acceptable())
				return Messages.get("problem.passwordShort", PasswordRating.MIN_LENGTH);
			if (!first.getText().equals(second.getText()))
				return Messages.get("problem.passwordMismatch");
			return null;
		}

		/** The password as chars; clears both fields. JavaFX keeps the text as a String internally. */
		char[] take()
		{
			char[] pw = first.getText().toCharArray();
			first.clear();
			second.clear();
			return pw;
		}
	}

	/** Choice between the default and the strong Argon2id profile. */
	static ChoiceBox<Argon2Params> argon2Choice()
	{
		ChoiceBox<Argon2Params> c = new ChoiceBox<>();
		c.getItems().addAll(Argon2Params.DEFAULT, Argon2Params.STRONG);
		c.setValue(Argon2Params.DEFAULT);
		c.setConverter(new StringConverter<>()
		{
			@Override
			public String toString(Argon2Params p)
			{
				return p == null ? "" : Messages.get(p.equals(Argon2Params.STRONG) ? "kdf.strong" : "kdf.default");
			}

			@Override
			public Argon2Params fromString(String s)
			{
				return null;
			}
		});
		return c;
	}

	static <T> StringConverter<T> converter(java.util.function.Function<T, String> f)
	{
		return new StringConverter<>()
		{
			@Override
			public String toString(T t)
			{
				return t == null ? "" : f.apply(t);
			}

			@Override
			public T fromString(String s)
			{
				return null;
			}
		};
	}
}
