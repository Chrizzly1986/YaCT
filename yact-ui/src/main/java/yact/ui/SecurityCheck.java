/*******************************************************************************
 * YaCT | (c) 2015-2026 Christian Hoppe | http://opensource.org/licenses/MIT
 ******************************************************************************/
package yact.ui;

import java.io.IOException;
import java.lang.management.ManagementFactory;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFileAttributeView;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.LocalDate;
import java.time.format.DateTimeParseException;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import yact.core.container.Container;
import yact.core.container.ProgressListener;
import yact.core.container.VerificationReport;
import yact.core.crypto.Argon2Params;
import yact.core.crypto.CryptoCapabilities;
import yact.core.crypto.CryptoCapabilities.Capability;
import yact.core.crypto.JdkCrypto;
import yact.core.format.HybridKeySlot;
import yact.core.format.KeySlot;
import yact.core.format.PasswordKeySlot;

/**
 * The security check the user starts from the Help menu. It checks this
 * installation and, if one is open, the container, and says in plain words
 * what is fine, what should be improved and what is a real problem.
 *
 * <p>Gathering the facts ({@link #environment()}, {@link #container}) is
 * separate from judging them ({@link #evaluate(Environment)},
 * {@link #evaluate(ContainerFacts)}), so the judgement can be tested with any
 * facts.
 */
final class SecurityCheck
{
	enum Level
	{
		OK, INFO, WARNING, CRITICAL
	}

	/** Repairs a finding; runs on the worker thread. */
	@FunctionalInterface
	interface Fix
	{
		void run() throws IOException;
	}

	/** One result of the check; {@code fix} is {@code null} if YaCT cannot repair it by itself. */
	record Finding(Level level, String text, Fix fix)
	{
		Finding(Level level, String text)
		{
			this(level, text, null);
		}
	}

	/** Facts about the running installation. */
	record Environment(List<Capability> crypto, String providers, List<String> injection, boolean modular,
			List<String> openings, boolean packaged, List<String> jvmArgs, boolean nativesInRuntime, Path installDir,
			boolean installWritable, String javaVersion, LocalDate javaDate, LocalDate today)
	{
	}

	/** Facts about the open container. {@code permissions} is {@code null} where the file system has none. */
	record ContainerFacts(Path file, VerificationReport verification, List<KeySlot> slots,
			Set<PosixFilePermission> permissions, Fix restrictPermissions)
	{
	}

	/** Everything the dialog shows. */
	record Result(Path container, List<Capability> crypto, List<Finding> findings)
	{
		Level worst()
		{
			return findings.stream().map(Finding::level).max(Level::compareTo).orElse(Level.OK);
		}

		long count(Level level)
		{
			return findings.stream().filter(f -> f.level() == level).count();
		}
	}

	/** Options the packaged application starts with; see packaging/package.sh. */
	static final List<String> HARDENING = List.of("-XX:+DisableAttachMechanism", "-XX:-CreateCoredumpOnCrash");

	/** Java receives security updates every three months; older than two release cycles is out of date. */
	static final int MAX_JAVA_AGE_DAYS = 183;

	/** Folder names of common synchronisation services, matched against the container's path. */
	private static final List<String[]> SYNC_FOLDERS = List.of(
			new String[] { "Dropbox", "Dropbox" }, new String[] { "OneDrive", "OneDrive" },
			new String[] { "iCloud Drive", "iCloud" }, new String[] { "iCloudDrive", "iCloud" },
			new String[] { "Mobile Documents", "iCloud" }, new String[] { "Google Drive", "Google Drive" },
			new String[] { "GoogleDrive", "Google Drive" }, new String[] { "My Drive", "Google Drive" },
			new String[] { "Nextcloud", "Nextcloud" }, new String[] { "ownCloud", "ownCloud" },
			new String[] { "pCloud", "pCloud" }, new String[] { "pCloudDrive", "pCloud" }, new String[] { "MEGA", "MEGA" },
			new String[] { "MEGAsync", "MEGA" }, new String[] { "Box", "Box" }, new String[] { "Box Sync", "Box" },
			new String[] { "Seafile", "Seafile" }, new String[] { "SynologyDrive", "Synology Drive" },
			new String[] { "Tresorit", "Tresorit" }, new String[] { "Proton Drive", "Proton Drive" });

	private SecurityCheck()
	{
	}

	/** Runs the whole check; {@code container} may be {@code null}. Call on the worker thread. */
	static Result run(Container container, ProgressListener progress) throws IOException
	{
		Environment env = environment();
		List<Finding> findings = new ArrayList<>(evaluate(env));
		Path file = null;
		if (container != null && container.isOpen())
		{
			file = container.file();
			findings.addAll(evaluate(container(container, progress)));
		}
		findings.add(new Finding(Level.INFO, Messages.get("check.limits")));
		return new Result(file, env.crypto(), findings);
	}

	// ================================================================== gathering

	static Environment environment()
	{
		List<Capability> crypto = CryptoCapabilities.check();
		String providers;
		try
		{
			providers = JdkCrypto.describe();
		}
		catch (RuntimeException | LinkageError e)
		{
			providers = String.valueOf(e.getMessage());
		}
		Module core = Container.class.getModule();
		boolean packaged = Boolean.getBoolean("yact.packaged");
		Path javaHome = Path.of(System.getProperty("java.home"));
		return new Environment(crypto, providers, RuntimeChecks.current(), core.isNamed(),
				openings(List.of(core, SecurityCheck.class.getModule())), packaged,
				ManagementFactory.getRuntimeMXBean().getInputArguments(), nativesIn(javaHome), javaHome,
				packaged && Files.isWritable(javaHome), System.getProperty("java.version", "?"),
				parseDate(System.getProperty("java.version.date")), LocalDate.now());
	}

	/**
	 * Packages of YaCT's modules that are open to other modules for deep reflection, or exported beyond
	 * what the module descriptors declare. Either would let other code reach keys.
	 */
	static List<String> openings(List<Module> modules)
	{
		List<Module> others = new ArrayList<>(ModuleLayer.boot().modules());
		others.add(ClassLoader.getSystemClassLoader().getUnnamedModule());
		others.add(ClassLoader.getPlatformClassLoader().getUnnamedModule());
		List<String> found = new ArrayList<>();
		for (Module m : modules)
		{
			if (!m.isNamed())
				continue;
			var declared = m.getDescriptor().exports();
			for (String pkg : m.getPackages())
				for (Module other : others)
				{
					if (other == m)
						continue;
					String name = other.isNamed() ? other.getName() : "ALL-UNNAMED";
					if (m.isOpen(pkg, other))
						found.add(m.getName() + "/" + pkg + " → " + name + " (open)");
					else if (m.isExported(pkg, other) && declared.stream().noneMatch(
							e -> e.source().equals(pkg) && (!e.isQualified() || e.targets().contains(name))))
						found.add(m.getName() + "/" + pkg + " → " + name + " (exported)");
				}
		}
		return found.stream().distinct().toList();
	}

	/** True if JavaFX's native libraries are inside the Java runtime (lib on Linux and macOS, bin on Windows). */
	static boolean nativesIn(Path javaHome)
	{
		for (String dir : List.of("lib", "bin"))
		{
			Path d = javaHome.resolve(dir);
			if (!Files.isDirectory(d))
				continue;
			try (Stream<Path> files = Files.list(d))
			{
				if (files.map(p -> p.getFileName().toString().toLowerCase(Locale.ROOT))
						.anyMatch(n -> n.startsWith("libglass") || n.equals("glass.dll")))
					return true;
			}
			catch (IOException e)
			{
				// not readable: treated as absent
			}
		}
		return false;
	}

	private static LocalDate parseDate(String s)
	{
		try
		{
			return s == null ? null : LocalDate.parse(s);
		}
		catch (DateTimeParseException e)
		{
			return null;
		}
	}

	static ContainerFacts container(Container c, ProgressListener progress) throws IOException
	{
		VerificationReport v = c.verify(progress);
		Path file = c.file();
		PosixFileAttributeView view = Files.getFileAttributeView(file, PosixFileAttributeView.class);
		Set<PosixFilePermission> perms = view == null ? null : view.readAttributes().permissions();
		Fix restrict = view == null ? null
				: () -> Files.setPosixFilePermissions(file,
						EnumSet.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE));
		return new ContainerFacts(file, v, c.header().keySlots(), perms, restrict);
	}

	// ================================================================== judging

	static List<Finding> evaluate(Environment env)
	{
		List<Finding> out = new ArrayList<>();

		List<Capability> failed = env.crypto().stream().filter(c -> !c.available()).toList();
		if (failed.isEmpty() && !env.crypto().isEmpty())
			out.add(new Finding(Level.OK, Messages.get("check.crypto.ok", env.crypto().size(), env.providers())));
		else
			out.add(new Finding(Level.CRITICAL, Messages.get("check.crypto.failed",
					failed.stream().map(c -> c.name() + " (" + c.detail() + ")").collect(Collectors.joining("; ")))));

		if (env.injection().isEmpty())
			out.add(new Finding(Level.OK, Messages.get("check.injection.ok")));
		else
			out.add(new Finding(Level.CRITICAL, Messages.get("check.injection.found", String.join("; ", env.injection()))));

		if (!env.modular())
			out.add(new Finding(Level.WARNING, Messages.get("check.modules.classPath")));
		else if (!env.openings().isEmpty())
			out.add(new Finding(Level.CRITICAL, Messages.get("check.modules.open", String.join("; ", env.openings()))));
		else
			out.add(new Finding(Level.OK, Messages.get("check.modules.ok")));

		if (!env.packaged())
			out.add(new Finding(Level.WARNING, Messages.get("check.packaged.no")));
		else
		{
			out.add(new Finding(Level.OK, Messages.get("check.packaged.ok")));
			List<String> missing = HARDENING.stream().filter(o -> !env.jvmArgs().contains(o)).toList();
			if (missing.isEmpty())
				out.add(new Finding(Level.OK, Messages.get("check.hardening.ok")));
			else
				out.add(new Finding(Level.WARNING, Messages.get("check.hardening.missing", String.join(", ", missing))));
			out.add(env.nativesInRuntime() ? new Finding(Level.OK, Messages.get("check.natives.ok"))
					: new Finding(Level.WARNING, Messages.get("check.natives.missing")));
			if (env.installWritable())
				out.add(new Finding(Level.INFO, Messages.get("check.install.writable", env.installDir())));
		}

		if (env.javaDate() == null)
			out.add(new Finding(Level.INFO, Messages.get("check.java.ok", env.javaVersion(), "?")));
		else if (ChronoUnit.DAYS.between(env.javaDate(), env.today()) > MAX_JAVA_AGE_DAYS)
			out.add(new Finding(Level.WARNING, Messages.get("check.java.old", env.javaVersion(), env.javaDate())));
		else
			out.add(new Finding(Level.OK, Messages.get("check.java.ok", env.javaVersion(), env.javaDate())));
		return out;
	}

	static List<Finding> evaluate(ContainerFacts facts)
	{
		List<Finding> out = new ArrayList<>();
		VerificationReport v = facts.verification();

		if (v.damaged().isEmpty())
			out.add(new Finding(Level.OK, Messages.get("check.files.ok", v.files(), Sizes.format(v.bytes()))));
		else
		{
			List<String> shown = v.damaged().stream().limit(10).toList();
			String list = String.join(", ", shown) + (v.damaged().size() > shown.size() ? ", …" : "");
			out.add(new Finding(Level.CRITICAL, Messages.get("check.files.damaged", v.damaged().size(), v.files(), list)));
		}
		out.add(v.headerIntact() && v.stateIntact() ? new Finding(Level.OK, Messages.get("check.disk.ok"))
				: new Finding(Level.CRITICAL, Messages.get("check.disk.changed")));
		out.add(v.olderStateWiped() ? new Finding(Level.INFO, Messages.get("check.older.wiped"))
				: new Finding(Level.OK, Messages.get("check.older.ok")));

		int passwords = 0;
		int keys = 0;
		boolean weakFound = false;
		for (int i = 0; i < facts.slots().size(); i++)
		{
			KeySlot s = facts.slots().get(i);
			if (s instanceof PasswordKeySlot p)
			{
				passwords++;
				Argon2Params a = p.params();
				if (a.isBelowRecommended())
				{
					weakFound = true;
					out.add(new Finding(Level.CRITICAL, Messages.get("check.slots.tooWeak", i + 1, kdf(a))));
				}
				else if (a.memoryKiB() < Argon2Params.DEFAULT.memoryKiB() || a.iterations() < Argon2Params.DEFAULT.iterations())
				{
					weakFound = true;
					out.add(new Finding(Level.WARNING,
							Messages.get("check.slots.weak", i + 1, kdf(a), kdf(Argon2Params.DEFAULT))));
				}
			}
			else if (s instanceof HybridKeySlot)
				keys++;
			else
				out.add(new Finding(Level.INFO, Messages.get("check.slots.unknown", i + 1)));
		}
		if (passwords > 0 && !weakFound)
			out.add(new Finding(Level.OK, Messages.get("check.slots.ok", kdf(Argon2Params.DEFAULT))));
		out.add(new Finding(Level.INFO, Messages.get("check.slots.count", passwords, keys)));

		if (facts.permissions() != null)
		{
			Set<PosixFilePermission> others = EnumSet.noneOf(PosixFilePermission.class);
			for (PosixFilePermission p : facts.permissions())
				if (p.name().startsWith("GROUP_") || p.name().startsWith("OTHERS_"))
					others.add(p);
			if (others.isEmpty())
				out.add(new Finding(Level.OK, Messages.get("check.perm.ok")));
			else
				out.add(new Finding(Level.WARNING,
						Messages.get("check.perm.open", PosixFilePermissions.toString(facts.permissions())),
						facts.restrictPermissions()));
		}

		String service = syncService(facts.file());
		if (service != null)
			out.add(new Finding(Level.INFO, Messages.get("check.cloud", service)));
		return out;
	}

	/** The synchronisation service whose folder contains {@code file}, or {@code null}. */
	static String syncService(Path file)
	{
		Path p = file.toAbsolutePath();
		for (int i = 0; i < p.getNameCount() - 1; i++)
		{
			String segment = p.getName(i).toString();
			for (String[] s : SYNC_FOLDERS)
				// "OneDrive - Company", "Dropbox (Personal)", "Nextcloud2" and the like
				if (segment.equalsIgnoreCase(s[0]) || segment.regionMatches(true, 0, s[0] + " ", 0, s[0].length() + 1)
						|| segment.regionMatches(true, 0, s[0] + "-", 0, s[0].length() + 1)
						|| (segment.length() > s[0].length() && segment.regionMatches(true, 0, s[0], 0, s[0].length())
								&& Character.isDigit(segment.charAt(s[0].length()))))
					return s[1];
		}
		return null;
	}

	private static String kdf(Argon2Params a)
	{
		return Messages.get("check.kdf", Sizes.format(a.memoryBytes()), a.iterations());
	}

	// ================================================================== report

	/** The result as plain text, e.g. to paste into a support request. Contains no secrets. */
	static String text(Result r, String version, java.time.ZonedDateTime when)
	{
		StringBuilder b = new StringBuilder();
		b.append(Messages.get("check.title")).append(" – YaCT ").append(version).append(" – ")
				.append(when.withNano(0).toOffsetDateTime()).append('\n');
		b.append(r.container() == null ? Messages.get("check.scope.noContainer")
				: Messages.get("check.scope.container", r.container().getFileName())).append("\n\n");
		for (Finding f : r.findings())
			b.append('[').append(Messages.get("check.level." + f.level())).append("] ").append(f.text()).append('\n');
		b.append('\n');
		for (Capability c : r.crypto())
			b.append(c.available() ? "  OK      " : "  FAILED  ").append(c.name()).append(" – ").append(c.detail()).append('\n');
		return b.toString();
	}
}
