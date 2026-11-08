/*******************************************************************************
 * YaCT | (c) 2015-2026 Christian Hoppe | http://opensource.org/licenses/MIT
 ******************************************************************************/
package yact.ui;

import java.time.ZonedDateTime;
import java.util.function.Consumer;

import javafx.beans.property.ReadOnlyStringWrapper;
import javafx.collections.FXCollections;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.Scene;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.control.ScrollPane;
import javafx.scene.control.TableColumn;
import javafx.scene.control.TableView;
import javafx.scene.control.TitledPane;
import javafx.scene.input.Clipboard;
import javafx.scene.input.ClipboardContent;
import javafx.scene.layout.HBox;
import javafx.scene.layout.Priority;
import javafx.scene.layout.Region;
import javafx.scene.layout.VBox;
import javafx.stage.Modality;
import javafx.stage.Stage;
import yact.core.crypto.CryptoCapabilities.Capability;
import yact.ui.SecurityCheck.Level;
import yact.ui.SecurityCheck.Result;

/** Shows the result of a {@link SecurityCheck}, worst findings first. */
final class SecurityCheckDialog
{
	private SecurityCheckDialog()
	{
	}

	/** @param onFix called after the dialog closed, with the fix the user chose */
	static void show(Stage owner, Result result, Consumer<SecurityCheck.Fix> onFix)
	{
		Stage dialog = new Stage();
		dialog.initOwner(owner);
		dialog.initModality(Modality.WINDOW_MODAL);
		dialog.setTitle(Messages.get("check.title"));

		Level worst = result.worst();
		Label summary = new Label(switch (worst)
		{
			case CRITICAL -> Messages.get("check.summary.critical");
			case WARNING -> Messages.get("check.summary.warning", result.count(Level.WARNING));
			default -> Messages.get("check.summary.ok");
		});
		summary.getStyleClass().addAll("check-summary", "check-summary-" + worst);
		summary.setGraphic(badge(worst));
		summary.setWrapText(true);
		Label scope = new Label(result.container() == null ? Messages.get("check.scope.noContainer")
				: Messages.get("check.scope.container", result.container().getFileName()));
		scope.setWrapText(true);
		scope.getStyleClass().add("hint");

		VBox rows = new VBox(8);
		rows.setPadding(new Insets(4, 12, 4, 4));
		SecurityCheck.Fix[] chosen = new SecurityCheck.Fix[1];
		result.findings().stream().sorted((a, b) -> b.level().compareTo(a.level())).forEach(f -> {
			Label text = new Label(f.text());
			text.setWrapText(true);
			text.setMinHeight(Region.USE_PREF_SIZE);
			text.setMaxWidth(Double.MAX_VALUE);
			HBox.setHgrow(text, Priority.ALWAYS);
			HBox row = new HBox(10, badge(f.level()), text);
			row.setAlignment(Pos.TOP_LEFT);
			if (f.fix() != null)
			{
				Button fix = new Button(Messages.get("check.fix"));
				fix.setMinWidth(Region.USE_PREF_SIZE);
				fix.setOnAction(e -> {
					chosen[0] = f.fix();
					dialog.close();
				});
				row.getChildren().add(fix);
			}
			rows.getChildren().add(row);
		});
		ScrollPane scroll = new ScrollPane(rows);
		scroll.setFitToWidth(true);
		scroll.setPrefViewportHeight(330);
		VBox.setVgrow(scroll, Priority.ALWAYS);

		TitledPane details = new TitledPane(Messages.get("check.details"), cryptoTable(result));
		details.setExpanded(false);
		details.setAnimated(false);

		Button copy = new Button(Messages.get("check.copy"));
		copy.setOnAction(e -> {
			ClipboardContent c = new ClipboardContent();
			c.putString(SecurityCheck.text(result, YactApp.VERSION, ZonedDateTime.now()));
			Clipboard.getSystemClipboard().setContent(c);
		});
		Button close = new Button(Messages.get("button.close"));
		close.setDefaultButton(true);
		close.setOnAction(e -> dialog.close());
		Region spacer = new Region();
		HBox.setHgrow(spacer, Priority.ALWAYS);

		VBox box = new VBox(10, summary, scope, scroll, details, new HBox(8, copy, spacer, close));
		box.setPadding(new Insets(16));
		box.setPrefWidth(760);
		Dialogs.noTruncation(box);
		dialog.setScene(new Scene(box));
		dialog.getScene().getStylesheets().addAll(owner.getScene().getStylesheets());
		dialog.showAndWait();
		if (chosen[0] != null)
			onFix.accept(chosen[0]);
	}

	/** A round symbol for the level; the text says the same for screen readers. */
	static Label badge(Level level)
	{
		Label l = new Label(switch (level)
		{
			case OK -> "✓";
			case INFO -> "i";
			case WARNING -> "!";
			case CRITICAL -> "×";
		});
		l.getStyleClass().addAll("check-badge", "check-" + level);
		l.setAccessibleText(Messages.get("check.level." + level));
		l.setMinWidth(Region.USE_PREF_SIZE);
		return l;
	}

	private static TableView<Capability> cryptoTable(Result result)
	{
		TableView<Capability> table = new TableView<>(FXCollections.observableList(result.crypto()));
		table.getColumns().add(column(Messages.get("selftest.status"),
				c -> c.available() ? Messages.get("selftest.ok") : Messages.get("selftest.failed")));
		table.getColumns().add(column(Messages.get("selftest.algorithm"), Capability::name));
		table.getColumns().add(column("PQ", c -> c.postQuantum() ? "✓" : ""));
		table.getColumns().add(column(Messages.get("selftest.purpose"), Capability::purpose));
		table.getColumns().add(column(Messages.get("selftest.detail"), Capability::detail));
		table.setColumnResizePolicy(TableView.CONSTRAINED_RESIZE_POLICY_FLEX_LAST_COLUMN);
		table.setPrefHeight(300);
		return table;
	}

	private static TableColumn<Capability, String> column(String title, java.util.function.Function<Capability, String> f)
	{
		TableColumn<Capability, String> col = new TableColumn<>(title);
		col.setCellValueFactory(c -> new ReadOnlyStringWrapper(f.apply(c.getValue())));
		return col;
	}
}
