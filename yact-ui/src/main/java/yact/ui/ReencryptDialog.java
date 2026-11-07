/*******************************************************************************
 * YaCT | (c) 2015-2026 Christian Hoppe | http://opensource.org/licenses/MIT
 ******************************************************************************/
package yact.ui;

import java.io.IOException;
import java.nio.file.Path;
import java.util.List;
import java.util.Optional;

import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.scene.Node;
import javafx.scene.control.Button;
import javafx.scene.control.ChoiceBox;
import javafx.scene.control.Dialog;
import javafx.scene.control.Label;
import javafx.scene.control.ListView;
import javafx.scene.layout.GridPane;
import javafx.scene.layout.HBox;
import javafx.scene.layout.VBox;
import javafx.stage.Window;
import yact.core.crypto.Argon2Params;
import yact.core.pq.HybridPublicKey;

/** New credentials for re-encrypting a container: a password, public keys, or both. */
final class ReencryptDialog extends Dialog<ReencryptDialog.Settings>
{
	/** {@code password} is null for public keys only. */
	record Settings(char[] password, Argon2Params params, List<HybridPublicKey> recipients)
	{
	}

	private final ObservableList<HybridPublicKey> keys = FXCollections.observableArrayList();

	ReencryptDialog(Window owner)
	{
		initOwner(owner);
		setTitle(Messages.get("reencrypt.title"));
		setHeaderText(Messages.get("reencrypt.header"));

		Label text = new Label(Messages.get("reencrypt.text"));
		text.setWrapText(true);
		text.setPrefWidth(520);
		text.setMinHeight(javafx.scene.layout.Region.USE_PREF_SIZE);

		Dialogs.PasswordPair password = new Dialogs.PasswordPair();
		ChoiceBox<Argon2Params> kdf = Dialogs.argon2Choice();
		GridPane g = Dialogs.grid();
		g.setPadding(javafx.geometry.Insets.EMPTY);
		int row = password.addTo(g, 0);
		Label hint = new Label(Messages.get("reencrypt.passwordHint"));
		hint.getStyleClass().add("hint");
		g.add(hint, 1, row++);
		g.addRow(row++, new Label(Messages.get("label.kdf")), kdf);

		ListView<HybridPublicKey> list = new ListView<>(keys);
		list.setPrefHeight(110);
		list.setCellFactory(v -> new javafx.scene.control.ListCell<>()
		{
			@Override
			protected void updateItem(HybridPublicKey k, boolean empty)
			{
				super.updateItem(k, empty);
				setText(empty || k == null ? null : k.kem().displayName() + "   " + k.fingerprint());
			}
		});
		Button add = new Button(Messages.get("reencrypt.addKey"));
		add.setOnAction(e -> addKey());
		Button remove = new Button(Messages.get("reencrypt.removeKey"));
		remove.disableProperty().bind(list.getSelectionModel().selectedItemProperty().isNull());
		remove.setOnAction(e -> keys.remove(list.getSelectionModel().getSelectedItem()));

		Label problem = new Label();
		problem.getStyleClass().add("problem");
		VBox box = new VBox(10, text, g, new Label(Messages.get("reencrypt.keys")), list, new HBox(8, add, remove), problem);
		box.setPadding(new javafx.geometry.Insets(16));
		getDialogPane().setContent(box);
		getDialogPane().getButtonTypes().addAll(Dialogs.OK, Dialogs.CANCEL);

		Node ok = getDialogPane().lookupButton(Dialogs.OK);
		Runnable check = () -> {
			boolean noPassword = password.first.getText().isEmpty() && password.second.getText().isEmpty();
			String p = noPassword ? (keys.isEmpty() ? Messages.get("reencrypt.problem") : null) : password.problem();
			ok.setDisable(p != null);
			problem.setText(password.second.getText().isEmpty() && !noPassword ? "" : p == null ? "" : p);
		};
		password.first.textProperty().addListener(x -> check.run());
		password.second.textProperty().addListener(x -> check.run());
		keys.addListener((javafx.collections.ListChangeListener<HybridPublicKey>) c -> check.run());
		check.run();
		Dialogs.noTruncation(this);

		setResultConverter(b -> {
			if (b != Dialogs.OK)
				return null;
			char[] pw = password.first.getText().isEmpty() ? null : password.take();
			return new Settings(pw, kdf.getValue(), List.copyOf(keys));
		});
	}

	private void addKey()
	{
		Optional<Path> file = Dialogs.open(getOwner(), Messages.get("reencrypt.addKey"), Dialogs.PUBLIC_KEYS);
		if (file.isEmpty())
			return;
		try
		{
			HybridPublicKey k = KeyIO.readPublicKey(file.get());
			if (!keys.contains(k))
				keys.add(k);
		}
		catch (IOException e)
		{
			ErrorMessages.show(getOwner(), e);
		}
	}
}
