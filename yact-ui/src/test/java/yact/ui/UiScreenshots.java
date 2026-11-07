/*******************************************************************************
 * YaCT | (c) 2015-2026 Christian Hoppe | http://opensource.org/licenses/MIT
 ******************************************************************************/
package yact.ui;

import java.awt.image.BufferedImage;
import java.io.ByteArrayInputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import javax.imageio.ImageIO;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;

import javafx.application.Platform;
import javafx.scene.Scene;
import javafx.scene.image.WritableImage;
import javafx.stage.Stage;
import javafx.stage.Window;
import yact.core.container.Container;
import yact.core.container.ProgressListener;
import yact.core.crypto.Argon2Params;
import yact.core.crypto.CipherSuite;
import yact.core.pq.HybridKem;
import yact.core.pq.HybridKeyPair;

/**
 * Renders every screen to PNG files for visual review. Needs a display; run with
 * {@code xvfb-run mvn -pl yact-ui test -Dtest=UiScreenshots -Dyact.screenshots=<dir>}, optionally with
 * {@code -Dyact.locale=fr} (default {@code de}).
 * Also fails if building any screen throws.
 */
@EnabledIfSystemProperty(named = "yact.screenshots", matches = ".+")
class UiScreenshots
{
	private static Path out;
	private static Path work;
	private static Stage stage;

	@BeforeAll
	static void start() throws Exception
	{
		Locale.setDefault(Locale.forLanguageTag(System.getProperty("yact.locale", "de")));
		out = Files.createDirectories(Path.of(System.getProperty("yact.screenshots")));
		work = Files.createTempDirectory("yact-ui");
		CountDownLatch started = new CountDownLatch(1);
		Platform.startup(started::countDown);
		started.await();
		Platform.setImplicitExit(false);
	}

	@AfterAll
	static void stop()
	{
		Platform.exit();
	}

	@Test
	void allScreens() throws Exception
	{
		// Main window with start screen.
		fx(() -> {
			stage = new Stage();
			new YactApp().start(stage);
		});
		pause(800);
		save("01-start", stage.getScene());
		if (stage.getIcons().size() != AppIcons.SIZES.length)
			throw new AssertionError("main window has " + stage.getIcons().size() + " icons");
		java.lang.reflect.Method about = YactApp.class.getDeclaredMethod("about");
		about.setAccessible(true);
		YactApp app = new YactApp();
		java.lang.reflect.Field stageField = YactApp.class.getDeclaredField("stage");
		stageField.setAccessible(true);
		stageField.set(app, stage);
		shootDialog("12-about", () -> {
			try
			{
				about.invoke(app);
			}
			catch (ReflectiveOperationException e)
			{
				throw new IllegalStateException(e);
			}
		}, w -> {
			if (!(w instanceof Stage s) || s.getIcons().isEmpty())
				throw new AssertionError("dialog window has no icon");
		});

		shootDialog("02-create-password", () -> new CreateContainerDialog(stage).show());
		shootDialog("03-create-key", () -> {
			CreateContainerDialog d = new CreateContainerDialog(stage);
			d.show();
			((javafx.scene.control.RadioButton) d.getDialogPane().lookupAll(".radio-button").toArray()[1]).setSelected(true);
		});
		shootDialog("04-unlock", () -> new UnlockDialog(stage, work.resolve("tresor.yact"), null).show());
		shootDialog("05-keypair", () -> new NewKeyPairDialog(stage).show());
		shootDialog("06-grow", () -> new GrowDialog(stage, work.resolve("t.yact"), 64L << 20, 40L << 20).show());

		// A container with some content, shown in the main window.
		Path file = work.resolve("tresor.yact");
		Container c = Container.create(file, CipherSuite.AES_256_GCM, "passwort123".toCharArray(),
				new Argon2Params(64, 1, 1), 64L << 20, ProgressListener.NONE);
		for (String p : List.of("Verträge/Mietvertrag 2026.pdf", "Verträge/Versicherung.pdf", "Fotos/Urlaub/IMG_0001.jpg",
				"Fotos/Urlaub/IMG_0002.jpg", "Steuer/2025/Erklärung.pdf", "Passwörter.kdbx", "Notizen.txt"))
			c.add(p, new ByteArrayInputStream(new byte[(int) (Math.abs(p.hashCode()) % 3_000_000)]),
					Instant.parse("2026-10-14T09:30:00Z"), false);
		c.addPublicKeySlot(HybridKeyPair.generate(HybridKem.DEFAULT, new java.security.SecureRandom()).publicKey());
		c.commit();
		ContainerView.Snapshot snap = ContainerView.Snapshot.of(c);
		AtomicReference<ContainerView> view = new AtomicReference<>();
		fx(() -> {
			Worker worker = new Worker(stage);
			ContainerView v = new ContainerView(stage, worker, c, snap);
			((javafx.scene.layout.BorderPane) stage.getScene().getRoot()).setCenter(v);
			view.set(v);
		});
		pause(500);
		save("07-container", stage.getScene());
		shootDialog("08-access", () -> view.get().manageAccess());

		// End to end through the UI logic: import a folder via the worker, as a drop or "Add folder" would.
		Path src = Files.createDirectories(work.resolve("Rechnungen/2026"));
		Files.writeString(src.resolve("Strom.txt"), "Stromrechnung Oktober");
		Files.write(src.getParent().resolve("Übersicht.csv"), new byte[200_000]);
		java.lang.reflect.Method addSources = ContainerView.class.getDeclaredMethod("addSources", List.class, String.class);
		addSources.setAccessible(true);
		fx(() -> {
			view.get().getChildrenUnmodifiable(); // on the UI thread, like a drop
			addSources.invoke(view.get(), List.of(work.resolve("Rechnungen")), "");
		});
		java.lang.reflect.Field snapField = ContainerView.class.getDeclaredField("snapshot");
		snapField.setAccessible(true);
		List<String> paths = List.of();
		for (int i = 0; i < 100; i++)
		{
			pause(100);
			AtomicReference<List<String>> now = new AtomicReference<>();
			fx(() -> now.set(((ContainerView.Snapshot) snapField.get(view.get())).entries().stream()
					.map(yact.core.container.ContainerEntry::path).toList()));
			paths = now.get();
			if (paths.contains("Rechnungen/2026/Strom.txt"))
				break;
		}
		if (!paths.contains("Rechnungen/2026/Strom.txt") || !paths.contains("Rechnungen/Übersicht.csv"))
			throw new AssertionError("import did not reach the view: " + paths);
		pause(300);
		save("11-after-import", stage.getScene());

		// Progress window of a long job.
		fx(() -> {
			Worker w = new Worker(stage);
			w.submit(Job.<Void>of("Container anlegen", true, j -> {
				j.message("Container wird mit Zufallsdaten gefüllt (4 GB) …");
				for (int i = 0; i <= 40; i++)
				{
					j.progress().progress(i, 100);
					Thread.sleep(50);
				}
				Thread.sleep(3000);
				return null;
			}), x -> {
			});
		});
		pause(2000);
		save("09-progress", lastWindow().getScene());
		pause(2500);

		// Error message.
		shootDialog("10-error", () -> Platform.runLater(
				() -> ErrorMessages.show(stage, new yact.core.format.InvalidCredentialsException())));
		// The import was committed: the content is readable from a fresh session.
		CountDownLatch closed = new CountDownLatch(1);
		fx(() -> view.get().close(closed::countDown));
		closed.await(30, TimeUnit.SECONDS);
		try (Container again = Container.open(file, "passwort123".toCharArray());
				java.io.InputStream in = again.read("Rechnungen/2026/Strom.txt"))
		{
			String text = new String(in.readAllBytes(), java.nio.charset.StandardCharsets.UTF_8);
			if (!text.equals("Stromrechnung Oktober"))
				throw new AssertionError("content after reopening: " + text);
		}
	}

	// ------------------------------------------------------------------ helpers

	/** Opens a window with {@code open}, saves its picture and closes it. */
	private static void shootDialog(String name, Runnable open) throws Exception
	{
		shootDialog(name, open, w -> {
		});
	}

	private static void shootDialog(String name, Runnable open, java.util.function.Consumer<Window> check) throws Exception
	{
		int before = Window.getWindows().size();
		Platform.runLater(open);
		for (int i = 0; i < 50 && Window.getWindows().size() <= before; i++)
			pause(100);
		pause(600);
		Window w = lastWindow();
		save(name, w.getScene());
		check.accept(w);
		fx(w::hide);
		pause(200);
	}

	private static Window lastWindow()
	{
		List<Window> windows = Window.getWindows();
		return windows.get(windows.size() - 1);
	}

	private static void save(String name, Scene scene) throws Exception
	{
		AtomicReference<WritableImage> img = new AtomicReference<>();
		fx(() -> img.set(scene.snapshot(null)));
		WritableImage fx = img.get();
		int w = (int) fx.getWidth();
		int h = (int) fx.getHeight();
		BufferedImage bi = new BufferedImage(w, h, BufferedImage.TYPE_INT_ARGB);
		for (int y = 0; y < h; y++)
			for (int x = 0; x < w; x++)
				bi.setRGB(x, y, fx.getPixelReader().getArgb(x, y));
		ImageIO.write(bi, "png", out.resolve(name + ".png").toFile());
	}

	private static void fx(ThrowingRunnable r) throws Exception
	{
		CountDownLatch done = new CountDownLatch(1);
		AtomicReference<Throwable> error = new AtomicReference<>();
		Platform.runLater(() -> {
			try
			{
				r.run();
			}
			catch (Throwable t)
			{
				error.set(t);
			}
			finally
			{
				done.countDown();
			}
		});
		if (!done.await(30, TimeUnit.SECONDS))
			throw new AssertionError("UI thread did not respond");
		if (error.get() != null)
			throw new AssertionError(error.get());
	}

	@FunctionalInterface
	private interface ThrowingRunnable
	{
		void run() throws Exception;
	}

	private static void pause(long ms) throws InterruptedException
	{
		Thread.sleep(ms);
	}
}
