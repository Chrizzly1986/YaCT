/*******************************************************************************
 * YaCT | (c) 2015-2026 Christian Hoppe | http://opensource.org/licenses/MIT
 ******************************************************************************/
package yact.ui;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import javafx.beans.Observable;
import javafx.scene.Node;
import javafx.scene.control.ChoiceBox;
import javafx.scene.control.Dialog;
import javafx.scene.control.Label;
import javafx.scene.control.RadioButton;
import javafx.scene.control.TextField;
import javafx.scene.control.TitledPane;
import javafx.scene.control.ToggleGroup;
import javafx.scene.layout.GridPane;
import javafx.scene.layout.HBox;
import javafx.scene.layout.VBox;
import javafx.stage.Window;
import yact.core.container.Container;
import yact.core.crypto.Argon2Params;
import yact.core.crypto.CipherSuite;
import yact.core.pq.HybridPublicKey;

/** Collects everything needed to create a container. */
final class CreateContainerDialog extends Dialog<CreateContainerDialog.Settings>
{
	/** Either {@code password} and {@code params}, or {@code recipient}, is set. */
	record Settings(Path file, long size, CipherSuite suite, char[] password, Argon2Params params,
			HybridPublicKey recipient)
	{
	}

	private final TextField path = new TextField();
	private final TextField size = new TextField("1");
	private final ChoiceBox<Sizes.Unit> unit = new ChoiceBox<>();
	private final RadioButton byPassword = new RadioButton(Messages.get("protect.password"));
	private final RadioButton byKey = new RadioButton(Messages.get("protect.publicKey"));
	private final Dialogs.PasswordPair password = new Dialogs.PasswordPair();
	private final ChoiceBox<Argon2Params> kdf = Dialogs.argon2Choice();
	private final TextField keyPath = new TextField();
	private final Label keyInfo = new Label();
	private final ChoiceBox<CipherSuite> suite = new ChoiceBox<>();
	private final Label problem = new Label();
	private HybridPublicKey recipient;

	CreateContainerDialog(Window owner)
	{
		initOwner(owner);
		setTitle(Messages.get("create.title"));
		setHeaderText(Messages.get("create.header"));

		unit.getItems().addAll(Sizes.Unit.values());
		unit.setConverter(Sizes.unitConverter());
		unit.setValue(Sizes.Unit.GB);
		ToggleGroup protect = new ToggleGroup();
		byPassword.setToggleGroup(protect);
		byKey.setToggleGroup(protect);
		byPassword.setSelected(true);
		suite.getItems().addAll(CipherSuite.values());
		suite.setValue(CipherSuite.AES_256_GCM);
		suite.setConverter(Dialogs.converter(s -> Messages.get("cipher." + s.name())));
		keyPath.setEditable(false);
		keyInfo.getStyleClass().add("hint");
		problem.getStyleClass().add("problem");
		problem.setWrapText(true);

		GridPane g = Dialogs.grid();
		int row = 0;
		g.addRow(row++, new Label(Messages.get("label.file")), Dialogs.pathField(path, this::browseFile));
		size.setPrefColumnCount(6);
		g.addRow(row++, new Label(Messages.get("label.size")), new HBox(6, size, unit));
		g.add(hint(Messages.get("create.sizeHint")), 1, row++);
		g.addRow(row++, new Label(Messages.get("label.protection")), new HBox(16, byPassword, byKey));

		GridPane pw = Dialogs.grid();
		pw.setPadding(javafx.geometry.Insets.EMPTY);
		int r = password.addTo(pw, 0);
		pw.addRow(r, new Label(Messages.get("label.kdf")), kdf);
		GridPane key = Dialogs.grid();
		key.setPadding(javafx.geometry.Insets.EMPTY);
		key.addRow(0, new Label(Messages.get("label.publicKey")), Dialogs.pathField(keyPath, this::browseKey));
		key.add(keyInfo, 1, 1);
		key.add(hint(Messages.get("create.keyHint")), 1, 2);
		VBox protection = new VBox(pw, key);
		key.visibleProperty().bind(byKey.selectedProperty());
		key.managedProperty().bind(byKey.selectedProperty());
		pw.visibleProperty().bind(byPassword.selectedProperty());
		pw.managedProperty().bind(byPassword.selectedProperty());
		g.add(protection, 0, row++, 2, 1);

		GridPane adv = Dialogs.grid();
		adv.addRow(0, new Label(Messages.get("label.cipher")), suite);
		adv.add(hint(Messages.get("create.cipherHint")), 1, 1);
		TitledPane advanced = new TitledPane(Messages.get("create.advanced"), adv);
		advanced.setExpanded(false);
		g.add(advanced, 0, row++, 2, 1);
		g.add(problem, 0, row, 2, 1);

		getDialogPane().setContent(g);
		getDialogPane().getButtonTypes().addAll(Dialogs.OK, Dialogs.CANCEL);
		Node ok = getDialogPane().lookupButton(Dialogs.OK);
		for (Observable o : new Observable[] { path.textProperty(), size.textProperty(), unit.valueProperty(),
				byPassword.selectedProperty(), password.first.textProperty(), password.second.textProperty(),
				keyPath.textProperty() })
			o.addListener(x -> ok.setDisable(validate() != null));
		ok.setDisable(true);
		problem.textProperty().set("");

		Dialogs.noTruncation(this);
		setResultConverter(b -> {
			if (b != Dialogs.OK)
				return null;
			Path file = Dialogs.withExtension(Path.of(path.getText().trim()), ".yact");
			long bytes = Sizes.parse(size.getText(), unit.getValue());
			return byPassword.isSelected()
					? new Settings(file, bytes, suite.getValue(), password.take(), kdf.getValue(), null)
					: new Settings(file, bytes, suite.getValue(), null, null, recipient);
		});
	}

	private static Label hint(String text)
	{
		Label l = new Label(text);
		l.getStyleClass().add("hint");
		l.setWrapText(true);
		l.setMaxWidth(420);
		return l;
	}

	/** Shows and returns the first problem, or null if everything is valid. */
	private String validate()
	{
		String p = findProblem();
		problem.setText(p == null || path.getText().isBlank() ? "" : p);
		return p;
	}

	private String findProblem()
	{
		if (path.getText().isBlank())
			return Messages.get("problem.noFile");
		Path file = Dialogs.withExtension(Path.of(path.getText().trim()), ".yact");
		if (Files.exists(file))
			return Messages.get("problem.fileExists");
		long bytes = Sizes.parse(size.getText(), unit.getValue());
		if (bytes < Container.MIN_SIZE)
			return Messages.get("problem.size", Sizes.format(Container.MIN_SIZE));
		long usable = Dialogs.usableSpace(file);
		if (usable >= 0 && bytes > usable)
			return Messages.get("problem.diskSpace", Sizes.format(usable));
		if (byPassword.isSelected())
			return password.problem();
		if (recipient == null)
			return Messages.get("problem.noKey");
		return null;
	}

	private void browseFile()
	{
		Dialogs.save(getOwner(), Messages.get("create.title"), "tresor.yact", Dialogs.CONTAINERS)
				.ifPresent(p -> path.setText(Dialogs.withExtension(p, ".yact").toString()));
	}

	private void browseKey()
	{
		Dialogs.open(getOwner(), Messages.get("label.publicKey"), Dialogs.PUBLIC_KEYS).ifPresent(p -> {
			try
			{
				recipient = KeyIO.readPublicKey(p);
				keyPath.setText(p.toString());
				keyInfo.setText(Messages.get("key.fingerprint", recipient.kem().displayName(), recipient.fingerprint()));
			}
			catch (IOException e)
			{
				recipient = null;
				keyPath.setText("");
				keyInfo.setText("");
				ErrorMessages.show(getOwner(), e);
			}
		});
	}
}
