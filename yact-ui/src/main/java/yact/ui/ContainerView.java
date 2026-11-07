/*******************************************************************************
 * YaCT | (c) 2015-2026 Christian Hoppe | http://opensource.org/licenses/MIT
 ******************************************************************************/
package yact.ui;

import java.io.File;
import java.io.IOException;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.time.format.FormatStyle;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import javafx.beans.binding.Bindings;
import javafx.beans.property.ReadOnlyObjectWrapper;
import javafx.beans.property.ReadOnlyStringWrapper;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.geometry.Insets;
import javafx.scene.Node;
import javafx.scene.control.Button;
import javafx.scene.control.ChoiceBox;
import javafx.scene.control.Dialog;
import javafx.scene.control.Label;
import javafx.scene.control.ListView;
import javafx.scene.control.SelectionMode;
import javafx.scene.control.Separator;
import javafx.scene.control.TextInputDialog;
import javafx.scene.control.ToolBar;
import javafx.scene.control.TreeItem;
import javafx.scene.control.TreeTableCell;
import javafx.scene.control.TreeTableColumn;
import javafx.scene.control.TreeTableRow;
import javafx.scene.control.TreeTableView;
import javafx.scene.input.TransferMode;
import javafx.scene.layout.BorderPane;
import javafx.scene.layout.GridPane;
import javafx.scene.layout.HBox;
import javafx.scene.layout.Priority;
import javafx.scene.layout.Region;
import javafx.scene.layout.VBox;
import javafx.stage.DirectoryChooser;
import javafx.stage.FileChooser;
import javafx.stage.Modality;
import javafx.stage.Stage;
import yact.core.container.Container;
import yact.core.container.ContainerEntry;
import yact.core.container.ContainerFullException;
import yact.core.container.VaultPaths;
import yact.core.crypto.Argon2Params;
import yact.core.format.HybridKeySlot;
import yact.core.format.KeySlot;
import yact.core.format.PasswordKeySlot;
import yact.core.pq.HybridPublicKey;

/** Shows an open container as a tree and offers all file and key slot operations. */
final class ContainerView extends BorderPane
{
	/** Everything the UI shows, taken on the worker thread after each job. */
	record Snapshot(List<ContainerEntry> entries, long size, long free, long freeForContent, List<String> slots)
	{
		static Snapshot of(Container c)
		{
			List<String> slots = new ArrayList<>();
			for (KeySlot s : c.header().keySlots())
				slots.add(describe(s));
			return new Snapshot(c.list(), c.size(), c.freeBytes(), c.freeBytesForContent(), slots);
		}

		private static String describe(KeySlot s)
		{
			if (s instanceof PasswordKeySlot p)
			{
				Argon2Params a = p.params();
				return Messages.get("slot.password", Sizes.format(a.memoryKiB() * 1024L), a.iterations(), a.parallelism());
			}
			if (s instanceof HybridKeySlot h)
				return Messages.get("slot.publicKey", h.kem().displayName());
			return Messages.get("slot.unknown", s.type());
		}
	}

	/** A row: a file, or a directory implied by the paths below it. */
	record Item(String name, String path, boolean directory, ContainerEntry entry, long size)
	{
	}

	private static final DateTimeFormatter DATE = DateTimeFormatter.ofLocalizedDateTime(FormatStyle.MEDIUM, FormatStyle.SHORT)
			.withLocale(Messages.locale()).withZone(ZoneId.systemDefault());

	private final Stage stage;
	private final Worker worker;
	private Container container;
	private Runnable onLost = () -> {
	};
	private final TreeTableView<Item> tree = new TreeTableView<>();
	private final Label status = new Label();
	private final ObservableList<String> slots = FXCollections.observableArrayList();
	private Snapshot snapshot;

	ContainerView(Stage stage, Worker worker, Container container, Snapshot initial)
	{
		this.stage = stage;
		this.worker = worker;
		this.container = container;

		setTop(toolbar());
		setCenter(tree);
		HBox bottom = new HBox(status);
		bottom.setPadding(new Insets(4, 8, 4, 8));
		bottom.getStyleClass().add("status-bar");
		setBottom(bottom);
		setupTree();
		Dialogs.noTruncation((javafx.scene.Parent) getTop());
		show(initial);
	}

	/** Called if the container had to be closed unexpectedly, e.g. after a failed re-encryption. */
	void setOnLost(Runnable onLost)
	{
		this.onLost = onLost;
	}

	Path file()
	{
		return container.file();
	}

	// ================================================================== layout

	private ToolBar toolbar()
	{
		Button addFiles = button("action.addFiles", this::addFilesChosen);
		Button addFolder = button("action.addFolder", this::addFolderChosen);
		Button extract = button("action.extract", this::extract);
		Button delete = button("action.delete", this::delete);
		Button rename = button("action.rename", this::rename);
		Button grow = button("action.grow", this::grow);
		Button access = button("action.access", this::manageAccess);

		var noSelection = Bindings.isEmpty(tree.getSelectionModel().getSelectedItems());
		extract.disableProperty().bind(noSelection.or(worker.busyProperty()));
		delete.disableProperty().bind(noSelection.or(worker.busyProperty()));
		rename.disableProperty().bind(Bindings.size(tree.getSelectionModel().getSelectedItems()).isNotEqualTo(1)
				.or(worker.busyProperty()));
		for (Button b : List.of(addFiles, addFolder, grow, access))
			b.disableProperty().bind(worker.busyProperty());

		Region spacer = new Region();
		HBox.setHgrow(spacer, Priority.ALWAYS);
		return new ToolBar(addFiles, addFolder, new Separator(), extract, rename, delete, spacer, grow, access);
	}

	private static Button button(String key, Runnable action)
	{
		Button b = new Button(Messages.get(key));
		b.setOnAction(e -> action.run());
		return b;
	}

	private void setupTree()
	{
		TreeTableColumn<Item, String> name = new TreeTableColumn<>(Messages.get("column.name"));
		name.setCellValueFactory(c -> new ReadOnlyStringWrapper(c.getValue().getValue().name()));
		name.setPrefWidth(380);
		TreeTableColumn<Item, Long> size = new TreeTableColumn<>(Messages.get("column.size"));
		size.setCellValueFactory(c -> new ReadOnlyObjectWrapper<>(c.getValue().getValue().size()));
		size.setCellFactory(col -> new TreeTableCell<>()
		{
			@Override
			protected void updateItem(Long v, boolean empty)
			{
				super.updateItem(v, empty);
				setText(empty || v == null ? null : Sizes.format(v));
			}
		});
		size.setStyle("-fx-alignment: CENTER-RIGHT;");
		size.setPrefWidth(100);
		TreeTableColumn<Item, String> modified = new TreeTableColumn<>(Messages.get("column.modified"));
		modified.setCellValueFactory(c -> {
			ContainerEntry e = c.getValue().getValue().entry();
			return new ReadOnlyStringWrapper(e == null ? "" : DATE.format(e.modified()));
		});
		modified.setPrefWidth(160);
		tree.getColumns().add(name);
		tree.getColumns().add(size);
		tree.getColumns().add(modified);
		tree.setShowRoot(false);
		tree.getSelectionModel().setSelectionMode(SelectionMode.MULTIPLE);
		tree.setColumnResizePolicy(TreeTableView.CONSTRAINED_RESIZE_POLICY_FLEX_LAST_COLUMN);
		tree.setPlaceholder(new Label(Messages.get("view.empty")));
		tree.setRowFactory(t -> new TreeTableRow<>()
		{
			@Override
			protected void updateItem(Item item, boolean empty)
			{
				super.updateItem(item, empty);
				getStyleClass().remove("directory");
				if (!empty && item != null && item.directory())
					getStyleClass().add("directory");
			}
		});

		tree.setOnDragOver(e -> {
			if (e.getDragboard().hasFiles() && !worker.busyProperty().get())
				e.acceptTransferModes(TransferMode.COPY);
			e.consume();
		});
		tree.setOnDragDropped(e -> {
			boolean ok = e.getDragboard().hasFiles();
			if (ok)
				addSources(e.getDragboard().getFiles().stream().map(File::toPath).toList(), targetDirectory());
			e.setDropCompleted(ok);
			e.consume();
		});
	}

	private void show(Snapshot s)
	{
		snapshot = s;
		slots.setAll(s.slots());

		Set<String> expanded = new HashSet<>();
		collectExpanded(tree.getRoot(), expanded);
		boolean first = tree.getRoot() == null;

		TreeItem<Item> root = new TreeItem<>(new Item("", "", true, null, 0));
		Map<String, TreeItem<Item>> dirs = new HashMap<>();
		dirs.put("", root);
		Map<TreeItem<Item>, long[]> dirSizes = new LinkedHashMap<>();
		for (ContainerEntry e : s.entries())
		{
			TreeItem<Item> parent = root;
			String[] parts = e.path().split("/");
			StringBuilder p = new StringBuilder();
			for (int i = 0; i < parts.length - 1; i++)
			{
				if (i > 0)
					p.append('/');
				p.append(parts[i]);
				String dirPath = p.toString();
				TreeItem<Item> pp = parent;
				int idx = i;
				parent = dirs.computeIfAbsent(dirPath, k -> {
					TreeItem<Item> d = new TreeItem<>(new Item(parts[idx], k, true, null, 0));
					pp.getChildren().add(d);
					return d;
				});
				dirSizes.computeIfAbsent(parent, k -> new long[1])[0] += e.size();
			}
			parent.getChildren().add(new TreeItem<>(new Item(e.name(), e.path(), false, e, e.size())));
		}
		for (Map.Entry<TreeItem<Item>, long[]> d : dirSizes.entrySet())
		{
			Item i = d.getKey().getValue();
			d.getKey().setValue(new Item(i.name(), i.path(), true, null, d.getValue()[0]));
		}
		sort(root);
		for (TreeItem<Item> d : dirs.values())
			d.setExpanded(d == root || expanded.contains(d.getValue().path()) || (first && d.getParent() == root));
		tree.setRoot(root);

		status.setText(Messages.get("status.summary", s.entries().size(), Sizes.format(s.freeForContent()),
				Sizes.format(s.size()), container.file().getFileName()));
	}

	private static void sort(TreeItem<Item> node)
	{
		node.getChildren().sort(Comparator.comparing((TreeItem<Item> t) -> !t.getValue().directory())
				.thenComparing(t -> t.getValue().name(), String.CASE_INSENSITIVE_ORDER));
		node.getChildren().forEach(ContainerView::sort);
	}

	private static void collectExpanded(TreeItem<Item> node, Set<String> out)
	{
		if (node == null)
			return;
		if (node.isExpanded())
			out.add(node.getValue().path());
		node.getChildren().forEach(c -> collectExpanded(c, out));
	}

	private List<Item> selection()
	{
		return tree.getSelectionModel().getSelectedItems().stream().filter(java.util.Objects::nonNull)
				.map(TreeItem::getValue).toList();
	}

	/** Where new files go: the selected directory, the directory of the selected file, or the root. */
	private String targetDirectory()
	{
		TreeItem<Item> t = tree.getSelectionModel().getSelectedItem();
		if (t == null)
			return "";
		Item i = t.getValue();
		if (i.directory())
			return i.path();
		int slash = i.path().lastIndexOf('/');
		return slash < 0 ? "" : i.path().substring(0, slash);
	}

	/** All files below the selected rows. */
	private List<ContainerEntry> selectedEntries()
	{
		Map<String, ContainerEntry> out = new LinkedHashMap<>();
		for (Item i : selection())
			for (ContainerEntry e : snapshot.entries())
				if (i.directory() ? e.path().startsWith(i.path() + "/") : e.path().equals(i.path()))
					out.put(e.path(), e);
		return new ArrayList<>(out.values());
	}

	// ================================================================== running jobs

	/** Runs a job that ends with a fresh snapshot; on failure shows the error and refreshes anyway. */
	private void run(Job<Snapshot> job)
	{
		worker.submit(job, this::show, e -> {
			if (e instanceof ContainerFullException)
			{
				if (Dialogs.confirm(stage, Messages.get("full.header"), ErrorMessages.describe(e), Messages.get("full.grow")))
				{
					refresh(this::grow);
					return;
				}
			}
			else
				ErrorMessages.show(stage, e);
			refresh(() -> {
			});
		});
	}

	private void refresh(Runnable then)
	{
		worker.submit(Job.<Snapshot>of(Messages.get("job.refresh"), false, j -> Snapshot.of(container)), s -> {
			show(s);
			then.run();
		});
	}

	// ================================================================== adding

	private void addFilesChosen()
	{
		FileChooser fc = new FileChooser();
		fc.setTitle(Messages.get("action.addFiles"));
		List<File> files = fc.showOpenMultipleDialog(stage);
		if (files != null)
			addSources(files.stream().map(File::toPath).toList(), targetDirectory());
	}

	private void addFolderChosen()
	{
		DirectoryChooser dc = new DirectoryChooser();
		dc.setTitle(Messages.get("action.addFolder"));
		File dir = dc.showDialog(stage);
		if (dir != null)
			addSources(List.of(dir.toPath()), targetDirectory());
	}

	private record Planned(Path source, String target, long size, boolean exists)
	{
	}

	/** Scans the sources, asks about existing files and space, then imports. */
	private void addSources(List<Path> sources, String targetDir)
	{
		Job<List<Planned>> scan = Job.of(Messages.get("job.scan"), true, job -> {
			List<Planned> plan = new ArrayList<>();
			for (Path src : sources)
			{
				Path base = src.toAbsolutePath().normalize().getParent();
				Files.walkFileTree(src, new SimpleFileVisitor<>()
				{
					@Override
					public FileVisitResult visitFile(Path f, BasicFileAttributes attrs)
					{
						job.checkCancelled();
						if (attrs.isRegularFile())
						{
							String rel = base == null ? f.getFileName().toString()
									: base.relativize(f.toAbsolutePath().normalize()).toString().replace(File.separatorChar, '/');
							String target = VaultPaths.normalize(VaultPaths.normalize(targetDir.isEmpty() ? rel : targetDir + "/" + rel));
							plan.add(new Planned(f, target, attrs.size(), container.entry(target).isPresent()));
						}
						return FileVisitResult.CONTINUE;
					}
				});
			}
			return plan;
		});
		worker.submit(scan, plan -> {
			if (plan.isEmpty())
				return;
			long total = plan.stream().mapToLong(Planned::size).sum();
			if (total > snapshot.freeForContent())
			{
				if (Dialogs.confirm(stage, Messages.get("full.header"),
						Messages.get("full.needed", Sizes.format(total), Sizes.format(snapshot.freeForContent())),
						Messages.get("full.grow")))
					grow();
				return;
			}
			List<Planned> existing = plan.stream().filter(Planned::exists).toList();
			Dialogs.Conflict decision = Dialogs.Conflict.SKIP;
			if (!existing.isEmpty())
			{
				Optional<Dialogs.Conflict> c = Dialogs.conflict(stage, existing.size(), existing.get(0).target());
				if (c.isEmpty())
					return;
				decision = c.get();
			}
			importPlanned(plan, decision == Dialogs.Conflict.REPLACE);
		});
	}

	private void importPlanned(List<Planned> plan, boolean replace)
	{
		long total = plan.stream().mapToLong(Planned::size).sum();
		run(Job.<Snapshot>of(Messages.get("job.import"), true, job -> {
			long done = 0;
			int n = 0;
			try
			{
				for (Planned p : plan)
				{
					n++;
					job.checkCancelled();
					if (p.exists() && !replace)
						continue;
					job.message(Messages.get("job.importFile", n, plan.size(), p.target()));
					container.importFile(p.source(), p.target(), replace, job.progress(done, total));
					done += p.size();
				}
			}
			finally
			{
				// Keep what was imported, also after cancelling or an error.
				container.commit();
			}
			return Snapshot.of(container);
		}));
	}

	// ================================================================== extracting

	private void extract()
	{
		List<Item> sel = selection();
		List<ContainerEntry> entries = selectedEntries();
		if (entries.isEmpty())
			return;
		Map<ContainerEntry, Path> targets = new LinkedHashMap<>();
		Map<ContainerEntry, String> relative = new LinkedHashMap<>(); // folder extraction: path below the base
		Path folderBase = null;
		boolean overwrite;
		if (sel.size() == 1 && !sel.get(0).directory())
		{
			FileChooser fc = new FileChooser();
			fc.setTitle(Messages.get("action.extract"));
			fc.setInitialFileName(sel.get(0).name());
			File f = fc.showSaveDialog(stage);
			if (f == null)
				return;
			targets.put(entries.get(0), f.toPath());
			overwrite = true; // the file chooser has asked already
		}
		else
		{
			DirectoryChooser dc = new DirectoryChooser();
			dc.setTitle(Messages.get("action.extract"));
			File dir = dc.showDialog(stage);
			if (dir == null)
				return;
			Path base = dir.toPath().toAbsolutePath().normalize();
			folderBase = base;
			for (Item i : sel)
			{
				int slash = i.path().lastIndexOf('/');
				String parent = slash < 0 ? "" : i.path().substring(0, slash + 1);
				for (ContainerEntry e : entries)
					if (e.path().equals(i.path()) || e.path().startsWith(i.path() + "/"))
					{
						String rel = e.path().substring(parent.length());
						Path t = base.resolve(rel.replace('/', File.separatorChar)).normalize();
						if (t.startsWith(base) && targets.putIfAbsent(e, t) == null)
							relative.put(e, rel);
					}
			}
			List<Path> existing = targets.values().stream().filter(p -> Files.exists(p, LinkOption.NOFOLLOW_LINKS)).toList();
			overwrite = false;
			if (!existing.isEmpty())
			{
				Optional<Dialogs.Conflict> c = Dialogs.conflict(stage, existing.size(), existing.get(0).toString());
				if (c.isEmpty())
					return;
				overwrite = c.get() == Dialogs.Conflict.REPLACE;
			}
		}
		boolean replace = overwrite;
		Path base = folderBase;
		long total = targets.keySet().stream().mapToLong(ContainerEntry::size).sum();
		run(Job.<Snapshot>of(Messages.get("job.extract"), true, job -> {
			long done = 0;
			int n = 0;
			for (Map.Entry<ContainerEntry, Path> t : targets.entrySet())
			{
				n++;
				job.checkCancelled();
				if (!replace && Files.exists(t.getValue(), LinkOption.NOFOLLOW_LINKS))
					continue;
				job.message(Messages.get("job.extractFile", n, targets.size(), t.getKey().path()));
				if (base == null)
					container.extract(t.getKey().path(), t.getValue(), replace, job.progress(done, total));
				else // checks the real path, so a planted link cannot redirect the file
					container.extractInto(t.getKey().path(), base, relative.get(t.getKey()), replace,
							job.progress(done, total));
				done += t.getKey().size();
			}
			return Snapshot.of(container);
		}));
	}

	// ================================================================== delete, rename

	private void delete()
	{
		List<Item> sel = selection();
		int count = selectedEntries().size();
		if (sel.isEmpty() || !Dialogs.confirm(stage, Messages.get("delete.header", count),
				Messages.get("delete.text"), Messages.get("action.delete")))
			return;
		run(Job.<Snapshot>of(Messages.get("job.delete"), false, job -> {
			for (Item i : sel)
			{
				if (i.directory())
					container.deleteDirectory(i.path());
				else if (container.entry(i.path()).isPresent())
					container.delete(i.path());
			}
			job.message(Messages.get("job.wipe"));
			container.commit();
			return Snapshot.of(container);
		}));
	}

	private void rename()
	{
		Item item = selection().get(0);
		TextInputDialog d = new TextInputDialog(item.path());
		d.initOwner(stage);
		d.setTitle(Messages.get("action.rename"));
		d.setHeaderText(Messages.get("rename.header"));
		d.getEditor().setPrefColumnCount(40);
		d.getDialogPane().getButtonTypes().setAll(Dialogs.OK, Dialogs.CANCEL);
		Optional<String> result = d.showAndWait().map(String::trim).filter(s -> !s.isEmpty() && !s.equals(item.path()));
		if (result.isEmpty())
			return;
		String to;
		try
		{
			to = VaultPaths.normalize(result.get());
		}
		catch (IllegalArgumentException e)
		{
			ErrorMessages.show(stage, e);
			return;
		}
		List<ContainerEntry> affected = item.directory() ? selectedEntries() : List.of(item.entry());
		run(Job.<Snapshot>of(Messages.get("job.rename"), false, job -> {
			for (ContainerEntry e : affected)
				container.rename(e.path(), item.directory() ? to + e.path().substring(item.path().length()) : to);
			container.commit();
			return Snapshot.of(container);
		}));
	}

	// ================================================================== size

	void grow()
	{
		new GrowDialog(stage, container.file(), snapshot.size(), snapshot.freeForContent()).showAndWait()
				.ifPresent(size -> run(Job.<Snapshot>of(Messages.get("job.grow"), true, job -> {
					container.grow(size, job.progress());
					return Snapshot.of(container);
				})));
	}

	void wipeFreeSpace()
	{
		if (!Dialogs.confirm(stage, Messages.get("wipe.header"), Messages.get("wipe.text", Sizes.format(snapshot.free())),
				Messages.get("wipe.ok")))
			return;
		run(Job.<Snapshot>of(Messages.get("job.wipeFree"), true, job -> {
			container.wipeFreeSpace(job.progress());
			return Snapshot.of(container);
		}));
	}

	// ================================================================== access (key slots)

	void manageAccess()
	{
		Stage dialog = new Stage();
		dialog.initOwner(stage);
		dialog.initModality(Modality.WINDOW_MODAL);
		dialog.setTitle(Messages.get("access.title"));

		ListView<String> list = new ListView<>(slots);
		list.setPrefHeight(180);
		Button addPassword = button("access.addPassword", this::addPassword);
		Button addKey = button("access.addKey", this::addPublicKey);
		Button remove = button("access.remove", () -> removeSlot(list.getSelectionModel().getSelectedIndex()));
		Button reencrypt = button("access.reencrypt", () -> {
			dialog.close();
			reencrypt();
		});
		reencrypt.disableProperty().bind(worker.busyProperty());
		Button close = button("button.close", dialog::close);
		remove.disableProperty().bind(list.getSelectionModel().selectedItemProperty().isNull()
				.or(Bindings.size(slots).lessThanOrEqualTo(1)).or(worker.busyProperty()));
		addPassword.disableProperty().bind(worker.busyProperty());
		addKey.disableProperty().bind(worker.busyProperty());

		Label intro = new Label(Messages.get("access.intro"));
		intro.setWrapText(true);
		Region spacer = new Region();
		HBox.setHgrow(spacer, Priority.ALWAYS);
		VBox box = new VBox(10, intro, list, new HBox(8, addPassword, addKey, remove, reencrypt, spacer, close));
		box.setPadding(new Insets(16));
		intro.setPrefWidth(600);
		intro.setMinHeight(javafx.scene.layout.Region.USE_PREF_SIZE);
		Dialogs.noTruncation(box);
		dialog.setScene(new javafx.scene.Scene(box));
		dialog.getScene().getStylesheets().addAll(stage.getScene().getStylesheets());
		dialog.showAndWait();
	}

	private void addPassword()
	{
		Dialog<NewKeyPairDialog.Settings> d = new Dialog<>();
		d.initOwner(stage);
		d.setTitle(Messages.get("access.addPassword"));
		d.setHeaderText(Messages.get("access.addPasswordHeader"));
		Dialogs.PasswordPair pw = new Dialogs.PasswordPair();
		ChoiceBox<Argon2Params> kdf = Dialogs.argon2Choice();
		GridPane g = Dialogs.grid();
		int row = pw.addTo(g, 0);
		g.addRow(row, new Label(Messages.get("label.kdf")), kdf);
		d.getDialogPane().setContent(g);
		d.getDialogPane().getButtonTypes().addAll(Dialogs.OK, Dialogs.CANCEL);
		Node ok = d.getDialogPane().lookupButton(Dialogs.OK);
		ok.disableProperty().bind(pw.valid.not());
		d.setResultConverter(b -> b == Dialogs.OK ? new NewKeyPairDialog.Settings(null, pw.take(), kdf.getValue()) : null);
		Dialogs.noTruncation(d);
		d.showAndWait().ifPresent(s -> run(Job.<Snapshot>of(Messages.get("job.addPassword"), false, job -> {
			try
			{
				container.addPasswordSlot(s.password(), s.params());
			}
			finally
			{
				java.util.Arrays.fill(s.password(), '\0');
			}
			return Snapshot.of(container);
		})));
	}

	private void addPublicKey()
	{
		Optional<Path> file = Dialogs.open(stage, Messages.get("access.addKey"), Dialogs.PUBLIC_KEYS);
		if (file.isEmpty())
			return;
		HybridPublicKey key;
		try
		{
			key = KeyIO.readPublicKey(file.get());
		}
		catch (IOException e)
		{
			ErrorMessages.show(stage, e);
			return;
		}
		if (!Dialogs.confirm(stage, Messages.get("access.addKeyHeader"),
				Messages.get("access.addKeyText", key.kem().displayName(), key.fingerprint()), Messages.get("access.addKeyOk")))
			return;
		run(Job.<Snapshot>of(Messages.get("job.addKey"), false, job -> {
			container.addPublicKeySlot(key);
			return Snapshot.of(container);
		}));
	}

	private void removeSlot(int index)
	{
		if (index < 0 || !Dialogs.confirm(stage, Messages.get("access.removeHeader", slots.get(index)),
				Messages.get("access.removeText"), Messages.get("access.remove")))
			return;
		worker.submit(Job.<Snapshot>of(Messages.get("job.removeSlot"), false, job -> {
			container.removeKeySlot(index);
			return Snapshot.of(container);
		}), s -> {
			show(s);
			if (Dialogs.confirm(stage, Messages.get("access.removedHeader"), Messages.get("access.removedText"),
					Messages.get("access.reencrypt")))
				reencrypt();
		});
	}

	// ================================================================== re-encryption

	void reencrypt()
	{
		Optional<ReencryptDialog.Settings> settings = new ReencryptDialog(stage).showAndWait();
		if (settings.isEmpty())
			return;
		ReencryptDialog.Settings s = settings.get();
		Container old = container;
		worker.submit(Job.<Object[]>of(Messages.get("job.reencrypt"), true, job -> {
			job.message(Messages.get("job.reencryptText"));
			try
			{
				Container fresh = old.reencrypt(s.password(), s.params(), s.recipients(), job.progress());
				return new Object[] { fresh, Snapshot.of(fresh) };
			}
			finally
			{
				if (s.password() != null)
					java.util.Arrays.fill(s.password(), '\0');
			}
		}), r -> {
			container = (Container) r[0];
			show((Snapshot) r[1]);
			Dialogs.info(stage, Messages.get("reencrypt.doneHeader"), Messages.get("reencrypt.doneText"));
		}, e -> {
			ErrorMessages.show(stage, e);
			if (!old.isOpen())
				onLost.run(); // the swap failed after the old container was released; the file is unchanged
		});
	}

	// ================================================================== closing

	/** Commits, wipes the keys and releases the file; then runs {@code then} on the UI thread. */
	void close(Runnable then)
	{
		worker.submit(Job.of(Messages.get("job.close"), false, job -> {
			container.close();
			return null;
		}), x -> then.run(), e -> {
			ErrorMessages.show(stage, e);
			then.run();
		});
	}
}
