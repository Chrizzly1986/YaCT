/*******************************************************************************
 * YaCT | (c) 2015-2026 Christian Hoppe | http://opensource.org/licenses/MIT
 ******************************************************************************/
package yact.ui;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

import javafx.application.Application;
import javafx.application.Platform;
import javafx.beans.binding.BooleanBinding;
import javafx.beans.binding.Bindings;
import javafx.beans.property.ObjectProperty;
import javafx.beans.property.ReadOnlyStringWrapper;
import javafx.beans.property.SimpleObjectProperty;
import javafx.collections.FXCollections;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.Scene;
import javafx.scene.control.Alert;
import javafx.scene.control.Alert.AlertType;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.control.Menu;
import javafx.scene.control.MenuBar;
import javafx.scene.control.MenuItem;
import javafx.scene.control.SeparatorMenuItem;
import javafx.scene.control.TableColumn;
import javafx.scene.control.TableView;
import javafx.scene.control.TextField;
import javafx.scene.image.ImageView;
import javafx.scene.input.KeyCombination;
import javafx.scene.layout.BorderPane;
import javafx.scene.layout.VBox;
import javafx.stage.Stage;
import yact.core.container.Container;
import yact.core.crypto.CryptoCapabilities;
import yact.core.crypto.CryptoCapabilities.Capability;
import yact.core.format.InvalidCredentialsException;
import yact.core.pq.HybridKeyPair;
import yact.core.pq.KeyFiles;
import yact.core.stream.WarmUp;

/** The YaCT desktop client. */
public class YactApp extends Application
{
	/** From the jar manifest; "dev" when running from the build directory. */
	public static final String VERSION = java.util.Objects.requireNonNullElse(
			YactApp.class.getPackage().getImplementationVersion(), "dev");

	private Stage stage;
	private Worker worker;
	private final BorderPane root = new BorderPane();
	private final ObjectProperty<ContainerView> view = new SimpleObjectProperty<>();
	private Path lastKeyFile;

	@Override
	public void start(Stage stage)
	{
		this.stage = stage;
		// Lets the first large file be encrypted at full speed; see WarmUp.
		WarmUp.startInBackground();
		AppIcons.install();
		stage.getIcons().setAll(AppIcons.all());
		worker = new Worker(stage);

		root.setTop(menu());
		showStart();
		Scene scene = new Scene(root, 900, 600);
		scene.getStylesheets().add(YactApp.class.getResource("yact.css").toExternalForm());
		stage.setScene(scene);
		stage.titleProperty().bind(Bindings.createStringBinding(
				() -> view.get() == null ? Messages.get("app.name")
						: Messages.get("app.titleWithFile", view.get().file().getFileName()),
				view));
		stage.setOnCloseRequest(e -> {
			e.consume();
			quit();
		});
		stage.show();

		List<String> args = getParameters() == null ? List.of() : getParameters().getRaw();
		if (!args.isEmpty())
			unlock(Path.of(args.get(0)));
	}

	// ================================================================== layout

	private MenuBar menu()
	{
		BooleanBinding busy = worker.busyProperty().or(Bindings.createBooleanBinding(() -> false));
		BooleanBinding noContainer = view.isNull();

		MenuItem create = item("menu.new", this::newContainer, "Shortcut+N");
		MenuItem open = item("menu.open", this::openContainer, "Shortcut+O");
		MenuItem close = item("menu.close", this::closeContainer, "Shortcut+W");
		MenuItem quit = item("menu.quit", this::quit, "Shortcut+Q");
		create.disableProperty().bind(busy);
		open.disableProperty().bind(busy);
		close.disableProperty().bind(busy.or(noContainer));
		Menu file = new Menu(Messages.get("menu.file"), null, create, open, close, new SeparatorMenuItem(), quit);

		MenuItem grow = item("action.grow", () -> view.get().grow(), null);
		MenuItem access = item("action.access", () -> view.get().manageAccess(), null);
		MenuItem wipe = item("menu.wipeFree", () -> view.get().wipeFreeSpace(), null);
		for (MenuItem m : List.of(grow, access, wipe))
			m.disableProperty().bind(busy.or(noContainer));
		Menu containerMenu = new Menu(Messages.get("menu.container"), null, grow, access, new SeparatorMenuItem(), wipe);

		MenuItem keyPair = item("menu.newKeyPair", this::newKeyPair, null);
		keyPair.disableProperty().bind(busy);
		Menu keys = new Menu(Messages.get("menu.keys"), null, keyPair);

		MenuItem selfTest = item("menu.selfTest", this::selfTest, null);
		selfTest.disableProperty().bind(busy);
		Menu help = new Menu(Messages.get("menu.help"), null, selfTest, item("menu.about", this::about, null));

		return new MenuBar(file, containerMenu, keys, help);
	}

	private static MenuItem item(String key, Runnable action, String accelerator)
	{
		MenuItem m = new MenuItem(Messages.get(key));
		m.setOnAction(e -> action.run());
		if (accelerator != null)
			m.setAccelerator(KeyCombination.keyCombination(accelerator));
		return m;
	}

	private void showStart()
	{
		ImageView logo = new ImageView(AppIcons.image(128));
		logo.setFitWidth(112);
		logo.setFitHeight(112);
		logo.setSmooth(true);
		Label title = new Label(Messages.get("app.name"));
		title.getStyleClass().add("start-title");
		Label subtitle = new Label(Messages.get("start.subtitle"));
		subtitle.getStyleClass().add("start-subtitle");
		Button create = startButton("start.new", this::newContainer);
		Button open = startButton("start.open", this::openContainer);
		Button keyPair = startButton("start.keyPair", this::newKeyPair);
		VBox box = new VBox(14, logo, title, subtitle, create, open, keyPair);
		box.setAlignment(Pos.CENTER);
		box.setPadding(new Insets(40));
		root.setCenter(box);
		view.set(null);
	}

	private Button startButton(String key, Runnable action)
	{
		Button b = new Button(Messages.get(key));
		b.getStyleClass().add("start-button");
		b.setMaxWidth(320);
		b.setOnAction(e -> action.run());
		b.disableProperty().bind(worker.busyProperty());
		return b;
	}

	private void showContainer(Container c, ContainerView.Snapshot s)
	{
		ContainerView v = new ContainerView(stage, worker, c, s);
		root.setCenter(v);
		view.set(v);
	}

	// ================================================================== container lifecycle

	private void newContainer()
	{
		if (view.get() != null)
		{
			view.get().close(() -> {
				showStart();
				newContainer();
			});
			return;
		}
		new CreateContainerDialog(stage).showAndWait().ifPresent(s -> worker.submit(
				Job.<Object[]>of(Messages.get("job.create"), true, job -> {
					job.message(Messages.get("job.createFill", Sizes.format(s.size())));
					Container c;
					try
					{
						c = s.password() != null
								? Container.create(s.file(), s.suite(), s.password(), s.params(), s.size(), job.progress())
								: Container.create(s.file(), s.suite(), s.recipient(), s.size(), job.progress());
					}
					finally
					{
						if (s.password() != null)
							Arrays.fill(s.password(), '\0');
					}
					return new Object[] { c, ContainerView.Snapshot.of(c) };
				}), r -> showContainer((Container) r[0], (ContainerView.Snapshot) r[1])));
	}

	private void openContainer()
	{
		Dialogs.open(stage, Messages.get("menu.open"), Dialogs.CONTAINERS).ifPresent(this::unlock);
	}

	/** Asks for credentials and opens; asks again after a wrong password. */
	private void unlock(Path file)
	{
		if (view.get() != null)
		{
			view.get().close(() -> {
				showStart();
				unlock(file);
			});
			return;
		}
		Optional<UnlockDialog.Credentials> creds = new UnlockDialog(stage, file, lastKeyFile).showAndWait();
		if (creds.isEmpty())
			return;
		UnlockDialog.Credentials c = creds.get();
		if (c.keyFile() != null)
			lastKeyFile = c.keyFile();
		worker.submit(Job.<Object[]>of(Messages.get("job.open"), false, job -> {
			Container container;
			try
			{
				if (c.password() != null)
					container = Container.open(file, c.password());
				else
					try (HybridKeyPair key = KeyFiles.decryptPrivateKey(KeyIO.readSmall(c.keyFile()), c.keyPassword()))
					{
						container = Container.open(file, key);
					}
			}
			finally
			{
				if (c.password() != null)
					Arrays.fill(c.password(), '\0');
				if (c.keyPassword() != null)
					Arrays.fill(c.keyPassword(), '\0');
			}
			return new Object[] { container, ContainerView.Snapshot.of(container) };
		}), r -> showContainer((Container) r[0], (ContainerView.Snapshot) r[1]), e -> {
			ErrorMessages.show(stage, e);
			if (e instanceof InvalidCredentialsException)
				unlock(file);
		});
	}

	private void closeContainer()
	{
		if (view.get() != null)
			view.get().close(this::showStart);
	}

	private void quit()
	{
		if (worker.busyProperty().get())
		{
			Dialogs.info(stage, Messages.get("quit.busyHeader"), Messages.get("quit.busyText"));
			return;
		}
		Runnable exit = () -> {
			worker.shutdown();
			Platform.exit();
		};
		if (view.get() != null)
			view.get().close(exit);
		else
			exit.run();
	}

	// ================================================================== keys

	private void newKeyPair()
	{
		Optional<NewKeyPairDialog.Settings> settings = new NewKeyPairDialog(stage).showAndWait();
		if (settings.isEmpty())
			return;
		NewKeyPairDialog.Settings s = settings.get();
		Optional<Path> priv = Dialogs.save(stage, Messages.get("keypair.savePrivate"), "schluessel.yactkey", Dialogs.PRIVATE_KEYS)
				.map(p -> Dialogs.withExtension(p, ".yactkey"));
		if (priv.isEmpty())
		{
			Arrays.fill(s.password(), '\0');
			return;
		}
		String base = priv.get().getFileName().toString().replaceFirst("\\.yactkey$", "");
		Optional<Path> pub = Dialogs.save(stage, Messages.get("keypair.savePublic"), base + ".yactpub", Dialogs.PUBLIC_KEYS)
				.map(p -> Dialogs.withExtension(p, ".yactpub"));
		if (pub.isEmpty())
		{
			Arrays.fill(s.password(), '\0');
			return;
		}
		worker.submit(Job.<String>of(Messages.get("job.keyPair"), false, job -> {
			try (HybridKeyPair key = HybridKeyPair.generate(s.kem(), new SecureRandom()))
			{
				Files.write(priv.get(), KeyFiles.encryptPrivateKey(key, s.password(), s.params(), new SecureRandom()));
				Files.writeString(pub.get(), key.publicKey().toArmored(), StandardCharsets.US_ASCII);
				lastKeyFile = priv.get();
				return key.publicKey().fingerprint();
			}
			finally
			{
				Arrays.fill(s.password(), '\0');
			}
		}), fingerprint -> {
			Alert a = Dialogs.alert(AlertType.INFORMATION, "");
			a.initOwner(stage);
			a.setTitle(Messages.get("app.name"));
			a.setHeaderText(Messages.get("keypair.done"));
			TextField fp = new TextField(fingerprint);
			fp.setEditable(false);
			fp.getStyleClass().add("fingerprint");
			Label text = new Label(Messages.get("keypair.doneText", priv.get().getFileName(), pub.get().getFileName()));
			text.setWrapText(true);
			a.getDialogPane().setContent(new VBox(10, text, fp));
			a.getDialogPane().setPrefWidth(560);
			a.showAndWait();
		});
	}

	// ================================================================== help

	private void selfTest()
	{
		worker.submit(Job.<List<Capability>>of(Messages.get("menu.selfTest"), false, job -> CryptoCapabilities.check()), caps -> {
			TableView<Capability> table = new TableView<>(FXCollections.observableList(caps));
			table.getColumns().add(column(Messages.get("selftest.status"),
					c -> c.available() ? Messages.get("selftest.ok") : Messages.get("selftest.failed")));
			table.getColumns().add(column(Messages.get("selftest.algorithm"), Capability::name));
			table.getColumns().add(column("PQ", c -> c.postQuantum() ? "✓" : ""));
			table.getColumns().add(column(Messages.get("selftest.purpose"), Capability::purpose));
			table.getColumns().add(column(Messages.get("selftest.detail"), Capability::detail));
			table.setColumnResizePolicy(TableView.CONSTRAINED_RESIZE_POLICY_FLEX_LAST_COLUMN);
			table.setPrefSize(860, 320);
			Alert a = Dialogs.alert(CryptoCapabilities.allAvailable(caps) ? AlertType.INFORMATION : AlertType.ERROR, "");
			a.initOwner(stage);
			a.setTitle(Messages.get("menu.selfTest"));
			a.setHeaderText(Messages.get(CryptoCapabilities.allAvailable(caps) ? "selftest.allOk" : "selftest.missing"));
			a.getDialogPane().setContent(table);
			a.setResizable(true);
			a.showAndWait();
		});
	}

	private static TableColumn<Capability, String> column(String title, java.util.function.Function<Capability, String> f)
	{
		TableColumn<Capability, String> col = new TableColumn<>(title);
		col.setCellValueFactory(c -> new ReadOnlyStringWrapper(f.apply(c.getValue())));
		return col;
	}

	private void about()
	{
		Alert a = Dialogs.alert(AlertType.INFORMATION, Messages.get("about.text"));
		a.initOwner(stage);
		a.setHeaderText(Messages.get("app.name") + " " + VERSION);
		ImageView logo = new ImageView(AppIcons.image(64));
		a.setGraphic(logo);
		a.showAndWait();
	}

	public static void main(String[] args)
	{
		launch(args);
	}
}
