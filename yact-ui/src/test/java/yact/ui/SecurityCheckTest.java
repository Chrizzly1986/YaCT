/*******************************************************************************
 * YaCT | (c) 2015-2026 Christian Hoppe | http://opensource.org/licenses/MIT
 ******************************************************************************/
package yact.ui;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFileAttributeView;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.LocalDate;
import java.time.ZonedDateTime;
import java.util.List;
import java.util.stream.Collectors;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import yact.core.container.Container;
import yact.core.container.ProgressListener;
import yact.core.container.VerificationReport;
import yact.core.crypto.Argon2Params;
import yact.core.crypto.CipherSuite;
import yact.core.crypto.CryptoCapabilities.Capability;
import yact.core.crypto.JdkCrypto;
import yact.core.pq.HybridKem;
import yact.core.pq.HybridKeyPair;
import yact.ui.SecurityCheck.ContainerFacts;
import yact.ui.SecurityCheck.Environment;
import yact.ui.SecurityCheck.Finding;
import yact.ui.SecurityCheck.Level;

class SecurityCheckTest
{
	private static final LocalDate TODAY = LocalDate.of(2026, 11, 8);
	private static final List<Capability> CRYPTO = List.of(new Capability("AES-256-GCM", "data", false, true, "SunJCE"),
			new Capability("ML-KEM-1024", "keys", true, true, "BouncyCastle"));

	@TempDir
	Path tmp;

	// ================================================================== installation

	private static Environment env(List<Capability> crypto, List<String> injection, boolean modular, List<String> openings,
			boolean packaged, List<String> jvmArgs, boolean natives, boolean writable, LocalDate javaDate)
	{
		return new Environment(crypto, "SUN, SunJCE, SunEC", injection, modular, openings, packaged, jvmArgs, natives,
				Path.of("/opt/yact/lib/runtime"), writable, "21.0.13", javaDate, TODAY);
	}

	private static Environment healthy()
	{
		return env(CRYPTO, List.of(), true, List.of(), true, SecurityCheck.HARDENING, true, false, TODAY.minusDays(20));
	}

	private static List<Level> levels(List<Finding> findings)
	{
		return findings.stream().map(Finding::level).toList();
	}

	private static Level worst(List<Finding> findings)
	{
		return findings.stream().map(Finding::level).max(Level::compareTo).orElseThrow();
	}

	@Test
	void healthyInstallationIsOk()
	{
		List<Finding> f = SecurityCheck.evaluate(healthy());
		assertEquals(List.of(Level.OK, Level.OK, Level.OK, Level.OK, Level.OK, Level.OK, Level.OK), levels(f),
				f.stream().map(Finding::text).collect(Collectors.joining("\n")));
	}

	@Test
	void installationProblemsAreRatedBySeverity()
	{
		List<Capability> broken = List.of(CRYPTO.get(0), new Capability("ML-KEM-1024", "keys", true, false, "wrong answer"));
		List<Finding> f = SecurityCheck.evaluate(env(broken, List.of(), true, List.of(), true, SecurityCheck.HARDENING, true,
				false, TODAY));
		assertEquals(Level.CRITICAL, f.get(0).level());
		assertTrue(f.get(0).text().contains("ML-KEM-1024 (wrong answer)"), f.get(0).text());

		assertEquals(Level.CRITICAL, worst(SecurityCheck.evaluate(env(CRYPTO, List.of("JVM option -javaagent:x.jar"), true,
				List.of(), true, SecurityCheck.HARDENING, true, false, TODAY))));
		assertEquals(Level.CRITICAL, worst(SecurityCheck.evaluate(env(CRYPTO, List.of(), true,
				List.of("yact.core/yact.core.format → ALL-UNNAMED (open)"), true, SecurityCheck.HARDENING, true, false, TODAY))));
		assertEquals(Level.WARNING, worst(SecurityCheck.evaluate(env(CRYPTO, List.of(), false, List.of(), true,
				SecurityCheck.HARDENING, true, false, TODAY))), "class path: no module protection");

		// Run from the build directory: one warning, no checks that only make sense for the package.
		List<Finding> dev = SecurityCheck.evaluate(env(CRYPTO, List.of(), true, List.of(), false, List.of(), false, true, TODAY));
		assertEquals(1, dev.stream().filter(x -> x.level() == Level.WARNING).count());
		assertEquals(5, dev.size());

		List<Finding> unhardened = SecurityCheck.evaluate(env(CRYPTO, List.of(), true, List.of(), true,
				List.of("-XX:+DisableAttachMechanism"), false, true, TODAY));
		assertEquals(2, unhardened.stream().filter(x -> x.level() == Level.WARNING).count(), "core dumps and natives");
		assertTrue(unhardened.stream().anyMatch(x -> x.text().contains("-XX:-CreateCoredumpOnCrash")));
		assertTrue(unhardened.stream().anyMatch(x -> x.level() == Level.INFO), "writable installation");
	}

	@Test
	void outdatedJavaIsAWarning()
	{
		Environment old = env(CRYPTO, List.of(), true, List.of(), true, SecurityCheck.HARDENING, true, false,
				TODAY.minusDays(SecurityCheck.MAX_JAVA_AGE_DAYS + 1));
		assertEquals(Level.WARNING, worst(SecurityCheck.evaluate(old)));
		Environment fresh = env(CRYPTO, List.of(), true, List.of(), true, SecurityCheck.HARDENING, true, false,
				TODAY.minusDays(SecurityCheck.MAX_JAVA_AGE_DAYS));
		assertEquals(Level.OK, worst(SecurityCheck.evaluate(fresh)));
		Environment unknown = env(CRYPTO, List.of(), true, List.of(), true, SecurityCheck.HARDENING, true, false, null);
		assertEquals(Level.INFO, worst(SecurityCheck.evaluate(unknown)));
	}

	/** The real modules: yact.core is opened to nobody; an opening done at run time is found. */
	@Test
	void openedPackagesAreFound()
	{
		Module core = Container.class.getModule();
		assertTrue(core.isNamed());
		assertEquals(List.of(), SecurityCheck.openings(List.of(core)));

		Module ui = SecurityCheck.class.getModule();
		Module unnamed = ClassLoader.getSystemClassLoader().getUnnamedModule();
		if (!ui.isOpen("yact.ui", unnamed))
			ui.addOpens("yact.ui", unnamed); // as --add-opens yact.ui/yact.ui=ALL-UNNAMED would
		assertTrue(SecurityCheck.openings(List.of(ui)).contains("yact.ui/yact.ui → ALL-UNNAMED (open)"),
				SecurityCheck.openings(List.of(ui)).toString());
	}

	@Test
	void nativeLibrariesAreFoundInTheRuntime() throws Exception
	{
		assertFalse(SecurityCheck.nativesIn(tmp));
		Files.createDirectories(tmp.resolve("lib"));
		Files.createFile(tmp.resolve("lib/libjava.so"));
		assertFalse(SecurityCheck.nativesIn(tmp));
		Files.createFile(tmp.resolve("lib/libglass.so"));
		assertTrue(SecurityCheck.nativesIn(tmp));

		Path win = tmp.resolve("win");
		Files.createDirectories(win.resolve("bin"));
		Files.createFile(win.resolve("bin/glass.dll"));
		assertTrue(SecurityCheck.nativesIn(win));
	}

	@Test
	void environmentCanBeGathered()
	{
		Environment env = SecurityCheck.environment();
		assertTrue(env.crypto().stream().allMatch(Capability::available));
		assertEquals(JdkCrypto.describe(), env.providers());
		assertTrue(env.modular());
		assertNotNull(env.javaDate(), "java.version.date");
	}

	// ================================================================== container

	@Test
	void containerFindings() throws Exception
	{
		Path file = tmp.resolve("vault.yact");
		try (Container c = Container.create(file, CipherSuite.AES_256_GCM, "first password".toCharArray(),
				new Argon2Params(64, 1, 1), 1L << 20, ProgressListener.NONE))
		{
			c.add("a.txt", new java.io.ByteArrayInputStream(new byte[1234]), java.time.Instant.now(), false);
			c.addPasswordSlot("second password".toCharArray(), new Argon2Params(32 * 1024, 2, 1));
			try (HybridKeyPair key = HybridKeyPair.generate(HybridKem.DEFAULT, JdkCrypto.random()))
			{
				c.addPublicKeySlot(key.publicKey());
			}

			ContainerFacts facts = SecurityCheck.container(c, ProgressListener.NONE);
			assertTrue(facts.verification().intact());
			List<Finding> f = SecurityCheck.evaluate(facts);
			String all = f.stream().map(x -> x.level() + " " + x.text()).collect(Collectors.joining("\n"));
			assertTrue(f.stream().anyMatch(x -> x.level() == Level.CRITICAL && x.text().contains(" 1 ")), all); // 64 KiB
			assertTrue(f.stream().anyMatch(x -> x.level() == Level.WARNING && x.text().contains(" 2 ")), all); // 32 MiB
			assertTrue(f.stream().anyMatch(x -> x.level() == Level.INFO && x.text().contains("2") && x.text().contains("1")),
					all);
			assertFalse(f.stream().anyMatch(x -> x.text().equals(Messages.get("check.slots.ok",
					Messages.get("check.kdf", Sizes.format(Argon2Params.DEFAULT.memoryBytes()), 3)))), "not all passwords strong");

			// Readable by others: a warning that YaCT can fix.
			PosixFileAttributeView posix = Files.getFileAttributeView(file, PosixFileAttributeView.class);
			assumeTrue(posix != null, "POSIX permissions");
			assertEquals("rw-------", PosixFilePermissions.toString(facts.permissions()), "new containers are private");
			assertTrue(f.stream().anyMatch(x -> x.level() == Level.OK && x.text().equals(Messages.get("check.perm.ok"))));
			Files.setPosixFilePermissions(file, PosixFilePermissions.fromString("rw-r--r--"));
			Finding perm = SecurityCheck.evaluate(SecurityCheck.container(c, ProgressListener.NONE)).stream()
					.filter(x -> x.fix() != null).findFirst().orElseThrow();
			assertEquals(Level.WARNING, perm.level());
			assertTrue(perm.text().contains("rw-r--r--"));
			perm.fix().run();
			assertEquals("rw-------", PosixFilePermissions.toString(Files.getPosixFilePermissions(file)));
		}
	}

	@Test
	void verificationResultsAreRated()
	{
		ContainerFacts ok = facts(new VerificationReport(3, 3000, List.of(), true, true, false));
		assertEquals(Level.INFO, worst(SecurityCheck.evaluate(ok)), "only the note on how many entries give access");

		List<Finding> damaged = SecurityCheck.evaluate(facts(new VerificationReport(3, 3000, List.of("x/y.pdf"), true, true, false)));
		assertEquals(Level.CRITICAL, damaged.get(0).level());
		assertTrue(damaged.get(0).text().contains("x/y.pdf"));

		assertEquals(Level.CRITICAL, worst(SecurityCheck.evaluate(facts(new VerificationReport(3, 3000, List.of(), false, true, false)))));
		assertEquals(Level.CRITICAL, worst(SecurityCheck.evaluate(facts(new VerificationReport(3, 3000, List.of(), true, false, false)))));
		List<Finding> wiped = SecurityCheck.evaluate(facts(new VerificationReport(3, 3000, List.of(), true, true, true)));
		assertEquals(Level.INFO, worst(wiped), "an older state was found and removed: nothing left to do");
		assertTrue(wiped.contains(new Finding(Level.INFO, Messages.get("check.older.wiped"))));

		List<String> many = java.util.stream.IntStream.range(0, 25).mapToObj(i -> "f" + i).toList();
		String text = SecurityCheck.evaluate(facts(new VerificationReport(30, 3000, many, true, true, false))).get(0).text();
		assertTrue(text.contains("f9, …") && !text.contains("f10"), text);
	}

	private static ContainerFacts facts(VerificationReport v)
	{
		return new ContainerFacts(Path.of("/home/u/vault.yact"), v, List.of(), null, null);
	}

	@Test
	void synchronisedFoldersAreRecognised()
	{
		assertEquals("Dropbox", SecurityCheck.syncService(Path.of("/home/u/Dropbox/work/vault.yact")));
		assertEquals("Dropbox", SecurityCheck.syncService(Path.of("/home/u/Dropbox (Personal)/vault.yact")));
		assertEquals("OneDrive", SecurityCheck.syncService(Path.of("/Users/u/OneDrive - Firma/vault.yact")));
		assertEquals("iCloud", SecurityCheck.syncService(Path.of("/Users/u/Library/Mobile Documents/com~apple~CloudDocs/v.yact")));
		assertEquals("Nextcloud", SecurityCheck.syncService(Path.of("/home/u/Nextcloud2/v.yact")));
		assertEquals("Google Drive", SecurityCheck.syncService(Path.of("/Volumes/GoogleDrive/My Drive/v.yact")));
		assertNull(SecurityCheck.syncService(Path.of("/home/u/Boxes/v.yact")));
		assertNull(SecurityCheck.syncService(Path.of("/home/u/Documents/Dropbox")), "the file name itself does not count");
		assertNull(SecurityCheck.syncService(Path.of("/home/u/Documents/vault.yact")));
	}

	@Test
	void reportTextListsEveryFinding()
	{
		SecurityCheck.Result r = new SecurityCheck.Result(Path.of("/home/u/vault.yact"), CRYPTO,
				List.of(new Finding(Level.OK, "all good"), new Finding(Level.WARNING, "be careful")));
		assertEquals(Level.WARNING, r.worst());
		assertEquals(1, r.count(Level.WARNING));
		String text = SecurityCheck.text(r, "1.0.0", ZonedDateTime.parse("2026-11-08T10:15:30.123+01:00"));
		assertTrue(text.contains("2026-11-08T10:15:30+01:00"), text);
		assertTrue(text.contains("] all good") && text.contains("] be careful"), text);
		assertTrue(text.contains("vault.yact") && !text.contains("/home/u"), "only the file name, not where it is");
		assertTrue(text.contains("ML-KEM-1024"));
	}
}
