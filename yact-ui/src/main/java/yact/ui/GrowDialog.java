/*******************************************************************************
 * YaCT | (c) 2015-2026 Christian Hoppe | http://opensource.org/licenses/MIT
 ******************************************************************************/
package yact.ui;

import java.nio.file.Path;

import javafx.scene.Node;
import javafx.scene.control.ChoiceBox;
import javafx.scene.control.Dialog;
import javafx.scene.control.Label;
import javafx.scene.control.TextField;
import javafx.scene.layout.GridPane;
import javafx.scene.layout.HBox;
import javafx.stage.Window;

/** Asks for the new, larger container size. */
final class GrowDialog extends Dialog<Long>
{
	GrowDialog(Window owner, Path file, long currentSize, long freeBytes)
	{
		initOwner(owner);
		setTitle(Messages.get("grow.title"));
		setHeaderText(Messages.get("grow.header", Sizes.format(currentSize), Sizes.format(freeBytes)));

		TextField size = new TextField();
		size.setPrefColumnCount(6);
		ChoiceBox<Sizes.Unit> unit = new ChoiceBox<>();
		unit.getItems().addAll(Sizes.Unit.values());
		unit.setConverter(Sizes.unitConverter());
		unit.setValue(currentSize >= Sizes.Unit.GB.factor ? Sizes.Unit.GB : Sizes.Unit.MB);
		Label problem = new Label();
		problem.getStyleClass().add("problem");

		GridPane g = Dialogs.grid();
		g.addRow(0, new Label(Messages.get("label.newSize")), new HBox(6, size, unit));
		g.add(problem, 0, 1, 2, 1);
		getDialogPane().setContent(g);
		getDialogPane().getButtonTypes().addAll(Dialogs.OK, Dialogs.CANCEL);
		Node ok = getDialogPane().lookupButton(Dialogs.OK);

		long usable = Dialogs.usableSpace(file);
		Runnable check = () -> {
			long bytes = Sizes.parse(size.getText(), unit.getValue());
			String p = null;
			if (bytes <= currentSize)
				p = Messages.get("problem.growSize", Sizes.format(currentSize));
			else if (usable >= 0 && bytes - currentSize > usable)
				p = Messages.get("problem.diskSpace", Sizes.format(usable));
			problem.setText(size.getText().isBlank() ? "" : p == null ? "" : p);
			ok.setDisable(p != null);
		};
		size.textProperty().addListener(x -> check.run());
		unit.valueProperty().addListener(x -> check.run());
		check.run();
		setOnShown(e -> size.requestFocus());

		Dialogs.noTruncation(this);
		setResultConverter(b -> b == Dialogs.OK ? Sizes.parse(size.getText(), unit.getValue()) : null);
	}
}
