/*******************************************************************************
 * YaCT | (c) 2015-2026 Christian Hoppe | http://opensource.org/licenses/MIT
 ******************************************************************************/
package yact.ui;

import java.nio.file.Path;

import javafx.scene.Node;
import javafx.scene.control.Dialog;
import javafx.scene.control.Label;
import javafx.scene.control.PasswordField;
import javafx.scene.control.RadioButton;
import javafx.scene.control.TextField;
import javafx.scene.control.ToggleGroup;
import javafx.scene.layout.GridPane;
import javafx.scene.layout.HBox;
import javafx.stage.Window;

/** Asks for a container password, or for a private key file and its password. */
final class UnlockDialog extends Dialog<UnlockDialog.Credentials>
{
	/** Either {@code password}, or {@code keyFile} with {@code keyPassword}. */
	record Credentials(char[] password, Path keyFile, char[] keyPassword)
	{
	}

	UnlockDialog(Window owner, Path container, Path lastKeyFile)
	{
		initOwner(owner);
		setTitle(Messages.get("unlock.title"));
		setHeaderText(Messages.get("unlock.header", container.getFileName()));

		RadioButton byPassword = new RadioButton(Messages.get("protect.password"));
		RadioButton byKey = new RadioButton(Messages.get("protect.privateKey"));
		ToggleGroup group = new ToggleGroup();
		byPassword.setToggleGroup(group);
		byKey.setToggleGroup(group);
		PasswordField password = new PasswordField();
		TextField keyFile = new TextField(lastKeyFile == null ? "" : lastKeyFile.toString());
		PasswordField keyPassword = new PasswordField();
		(lastKeyFile == null ? byPassword : byKey).setSelected(true);

		GridPane g = Dialogs.grid();
		g.addRow(0, new Label(Messages.get("label.unlockWith")), new HBox(16, byPassword, byKey));
		Label pwLabel = new Label(Messages.get("label.password"));
		g.addRow(1, pwLabel, password);
		Label keyLabel = new Label(Messages.get("label.privateKey"));
		HBox keyRow = Dialogs.pathField(keyFile, () -> Dialogs
				.open(owner, Messages.get("label.privateKey"), Dialogs.PRIVATE_KEYS)
				.ifPresent(p -> keyFile.setText(p.toString())));
		g.addRow(2, keyLabel, keyRow);
		Label keyPwLabel = new Label(Messages.get("label.keyPassword"));
		g.addRow(3, keyPwLabel, keyPassword);
		for (Node n : new Node[] { pwLabel, password })
		{
			n.visibleProperty().bind(byPassword.selectedProperty());
			n.managedProperty().bind(byPassword.selectedProperty());
		}
		for (Node n : new Node[] { keyLabel, keyRow, keyPwLabel, keyPassword })
		{
			n.visibleProperty().bind(byKey.selectedProperty());
			n.managedProperty().bind(byKey.selectedProperty());
		}

		getDialogPane().setContent(g);
		getDialogPane().getButtonTypes().addAll(Dialogs.OK, Dialogs.CANCEL);
		Node ok = getDialogPane().lookupButton(Dialogs.OK);
		Runnable check = () -> ok.setDisable(byPassword.isSelected() ? password.getText().isEmpty()
				: keyFile.getText().isBlank() || keyPassword.getText().isEmpty());
		password.textProperty().addListener(x -> check.run());
		keyFile.textProperty().addListener(x -> check.run());
		keyPassword.textProperty().addListener(x -> check.run());
		group.selectedToggleProperty().addListener(x -> check.run());
		check.run();
		setOnShown(e -> (byPassword.isSelected() ? password : keyPassword).requestFocus());

		Dialogs.noTruncation(this);
		setResultConverter(b -> {
			if (b != Dialogs.OK)
				return null;
			Credentials c = byPassword.isSelected()
					? new Credentials(password.getText().toCharArray(), null, null)
					: new Credentials(null, Path.of(keyFile.getText().trim()), keyPassword.getText().toCharArray());
			password.clear();
			keyPassword.clear();
			return c;
		});
	}
}
