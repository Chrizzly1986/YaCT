/*******************************************************************************
 * YaCT | (c) 2015-2026 Christian Hoppe | http://opensource.org/licenses/MIT
 ******************************************************************************/
package yact.ui;

import javafx.scene.Node;
import javafx.scene.control.ChoiceBox;
import javafx.scene.control.Dialog;
import javafx.scene.control.Label;
import javafx.scene.layout.GridPane;
import javafx.stage.Window;
import yact.core.crypto.Argon2Params;
import yact.core.pq.HybridKem;

/** Settings for a new key pair: scheme and the password protecting the private key file. */
final class NewKeyPairDialog extends Dialog<NewKeyPairDialog.Settings>
{
	record Settings(HybridKem kem, char[] password, Argon2Params params)
	{
	}

	NewKeyPairDialog(Window owner)
	{
		initOwner(owner);
		setTitle(Messages.get("keypair.title"));
		setHeaderText(Messages.get("keypair.header"));

		ChoiceBox<HybridKem> kem = new ChoiceBox<>();
		kem.getItems().addAll(HybridKem.MLKEM1024_X25519, HybridKem.MLKEM768_X25519);
		kem.setValue(HybridKem.DEFAULT);
		kem.setConverter(Dialogs.converter(k -> k == HybridKem.DEFAULT
				? Messages.get("keypair.recommended", k.displayName()) : k.displayName()));
		Dialogs.PasswordPair password = new Dialogs.PasswordPair();
		ChoiceBox<Argon2Params> kdf = Dialogs.argon2Choice();
		Label problem = new Label();
		problem.getStyleClass().add("problem");

		GridPane g = Dialogs.grid();
		g.addRow(0, new Label(Messages.get("label.scheme")), kem);
		int row = password.addTo(g, 1);
		g.addRow(row++, new Label(Messages.get("label.kdf")), kdf);
		Label hint = new Label(Messages.get("keypair.hint"));
		hint.setWrapText(true);
		hint.setMaxWidth(440);
		hint.getStyleClass().add("hint");
		g.add(hint, 0, row++, 2, 1);
		g.add(problem, 0, row, 2, 1);

		getDialogPane().setContent(g);
		getDialogPane().getButtonTypes().addAll(Dialogs.OK, Dialogs.CANCEL);
		Node ok = getDialogPane().lookupButton(Dialogs.OK);
		ok.disableProperty().bind(password.valid.not());
		password.second.textProperty().addListener(x -> problem.setText(
				password.second.getText().isEmpty() ? "" : String.valueOf(java.util.Objects.requireNonNullElse(password.problem(), ""))));

		Dialogs.noTruncation(this);
		setResultConverter(b -> b == Dialogs.OK ? new Settings(kem.getValue(), password.take(), kdf.getValue()) : null);
	}
}
