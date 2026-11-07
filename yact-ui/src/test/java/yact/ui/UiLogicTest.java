/*******************************************************************************
 * YaCT | (c) 2015-2026 Christian Hoppe | http://opensource.org/licenses/MIT
 ******************************************************************************/
package yact.ui;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.text.MessageFormat;
import java.util.List;
import java.util.Locale;
import java.util.Properties;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

import org.junit.jupiter.api.Test;

class UiLogicTest
{
	@Test
	void sizes()
	{
		Locale saved = Locale.getDefault();
		Locale.setDefault(Locale.ENGLISH);
		try
		{
			assertEquals("512 B", Sizes.format(512));
			assertEquals("1.5 KB", Sizes.format(1536));
			assertEquals("4 GB", Sizes.format(4L << 30));
			assertEquals("150 MB", Sizes.format(150L << 20));
		}
		finally
		{
			Locale.setDefault(saved);
		}
		assertEquals(3L << 29, Sizes.parse("1,5", Sizes.Unit.GB));
		assertEquals(3L << 29, Sizes.parse(" 1.5 ", Sizes.Unit.GB));
		assertEquals(100L << 20, Sizes.parse("100", Sizes.Unit.MB));
		for (String bad : new String[] { "", "0", "-1", "abc", "1e9", "1,2,3", "99999999999" })
			assertEquals(-1, Sizes.parse(bad, Sizes.Unit.MB), bad);
	}

	@Test
	void passwordRating()
	{
		assertEquals(PasswordRating.TOO_SHORT, PasswordRating.of("short"));
		assertEquals(PasswordRating.TOO_SHORT, PasswordRating.of("abcdefgh12"), "12 characters are required");
		assertEquals(PasswordRating.WEAK, PasswordRating.of("abcdefghijkl"));
		assertEquals(PasswordRating.WEAK, PasswordRating.of("aaaaaaaaaaaaaaaaaaaaaa"), "few distinct characters");
		assertEquals(PasswordRating.WEAK, PasswordRating.of("121212121212121212"), "few distinct characters");
		assertEquals(PasswordRating.OK, PasswordRating.of("Abcdefgh1234"));
		assertEquals(PasswordRating.OK, PasswordRating.of("abcdefghijklmn"));
		assertEquals(PasswordRating.STRONG, PasswordRating.of("Abcdefgh1234wxyz"));
		assertEquals(PasswordRating.STRONG, PasswordRating.of("correct horse battery"));
		assertEquals(PasswordRating.TOO_SHORT, PasswordRating.of("\uD83D\uDD12".repeat(11)), "counts code points, not chars");
	}

	private static final String[] LANGUAGES = { "", "_de", "_fr", "_es", "_pt" };

	/** Every key the code uses exists in every language, and every text is a valid message pattern. */
	@Test
	void messagesAreComplete() throws IOException
	{
		Properties en = load("messages.properties");
		for (String lang : LANGUAGES)
			assertEquals(new TreeSet<>(en.stringPropertyNames()), new TreeSet<>(load("messages" + lang + ".properties")
					.stringPropertyNames()), "messages" + lang + " has the same keys as English");

		Set<String> used = usedKeys();
		assertTrue(used.size() > 100, "found " + used.size() + " keys");
		Set<String> missing = new TreeSet<>(used);
		missing.removeAll(en.stringPropertyNames());
		assertEquals(Set.of(), missing, "keys used in the code but missing from the bundles");

		for (String lang : LANGUAGES)
		{
			Properties p = load("messages" + lang + ".properties");
			for (String key : p.stringPropertyNames())
			{
				String text = p.getProperty(key);
				if (text.matches("(?s).*\\{\\d}.*"))
					assertTrue(!text.contains("'"), "messages" + lang + ": " + key
							+ " uses a plain apostrophe, which MessageFormat treats as a quote; use \u2019");
				if (text.contains("{0}"))
				{
					String formatted = new MessageFormat(text).format(new Object[] { "A", "B", "C", "D" });
					assertTrue(!formatted.contains("{"), key + " has an unbalanced quote: " + formatted);
				}
			}
		}
	}

	@Test
	void runtimeChecksDetectInjection()
	{
		java.util.Set<String> mods = java.util.Set.of("java.base", "javafx.controls", "yact.core", "yact.ui",
				"org.bouncycastle.provider", "jdk.localedata");
		java.util.Map<String, String> noEnv = java.util.Map.of();
		assertEquals(List.of(), RuntimeChecks.problems(List.of("-Dyact.packaged=true", "-XX:+DisableAttachMechanism",
				"-Dfile.encoding=UTF-8"), noEnv, "", mods, true), "a clean packaged start");

		for (String bad : List.of("-javaagent:/tmp/spy.jar", "-agentlib:jdwp=transport=dt_socket", "-agentpath:/x.so",
				"--add-opens=yact.core/yact.core.format=ALL-UNNAMED", "--add-exports=yact.core/yact.core.crypto=ALL-UNNAMED",
				"-Djdk.module.addopens=yact.core/yact.core.format=ALL-UNNAMED", "--patch-module=yact.core=/tmp/evil",
				"-Xbootclasspath/a:/tmp/evil.jar", "-Djava.system.class.loader=Evil", "-Djava.security.properties=/tmp/p",
				"-XX:+EnableDynamicAgentLoading"))
			assertEquals(1, RuntimeChecks.problems(List.of(bad), noEnv, "", mods, false).size(), bad);

		// Harmless settings in JAVA_TOOL_OPTIONS (proxy, trust store) are fine; an agent in it is not.
		assertEquals(List.of(), RuntimeChecks.problems(List.of(),
				java.util.Map.of("JAVA_TOOL_OPTIONS", "-Dhttps.proxyHost=proxy -Djavax.net.ssl.trustStore=/etc/ssl/x"), "", mods, true));
		assertEquals(1, RuntimeChecks.problems(List.of(),
				java.util.Map.of("JDK_JAVA_OPTIONS", "-Dx=1 -javaagent:/tmp/spy.jar"), "", mods, false).size());

		// Packaged: nothing on the class path, no extra modules, no module path tricks.
		assertEquals(1, RuntimeChecks.problems(List.of(), noEnv, "/tmp/evil.jar", mods, true).size());
		java.util.Set<String> withEvil = new java.util.HashSet<>(mods);
		withEvil.add("com.evil.keylogger");
		assertEquals(1, RuntimeChecks.problems(List.of(), noEnv, "", withEvil, true).size());
		assertEquals(1, RuntimeChecks.problems(List.of("-Djdk.module.path=/tmp/mods"), noEnv, "", mods, true).size());
		assertEquals(List.of(), RuntimeChecks.problems(List.of("-Djdk.module.path=/x"), noEnv, "/dev/cp", withEvil, false),
				"module path and class path are normal during development");

		assertTrue(RuntimeChecks.developerOverride(List.of("-Dyact.dev=true"), false));
		assertTrue(!RuntimeChecks.developerOverride(List.of("-Dyact.dev=true"), true), "never in the packaged application");
	}

	/** Every icon size exists and has exactly that many pixels. */
	@Test
	void iconsExist() throws IOException
	{
		for (int size : AppIcons.SIZES)
		{
			try (InputStream in = UiLogicTest.class.getResourceAsStream("/yact/ui/icons/yact-" + size + ".png"))
			{
				assertTrue(in != null, "icon " + size + " missing");
				// PNG header: signature, IHDR length and type, then width, height, bit depth, colour type.
				java.nio.ByteBuffer h = java.nio.ByteBuffer.wrap(in.readNBytes(26));
				assertEquals(0x89504E47, h.getInt(0), "PNG signature of icon " + size);
				assertEquals(size, h.getInt(16), "width of icon " + size);
				assertEquals(size, h.getInt(20), "height of icon " + size);
				assertEquals(6, h.get(25), "icon " + size + " is RGBA, with transparent corners");
			}
		}
	}

	/** English means British English: spelling in the texts, and UK formats for every non-translated locale. */
	@Test
	void englishIsBritish() throws IOException
	{
		assertEquals(Locale.UK, Messages.effective(Locale.US));
		assertEquals(Locale.UK, Messages.effective(Locale.ENGLISH));
		assertEquals(Locale.UK, Messages.effective(Locale.ITALIAN), "untranslated languages fall back to British English");
		assertEquals(Locale.GERMANY, Messages.effective(Locale.GERMANY));
		assertEquals(Locale.forLanguageTag("pt-BR"), Messages.effective(Locale.forLanguageTag("pt-BR")));

		Pattern american = Pattern.compile("\\b(License|Licensing|Color|Behavior|Favorite|Organi[zs]ation|Center|Canceled|"
				+ "Canceling|Dialog|Analyze|Catalog|Gray|"
				+ "(organiz|recogniz|realiz|finaliz|initializ|authoriz|customiz|minimiz|maximiz|optimiz|synchroniz|"
				+ "categoriz|prioritiz|summariz|normaliz|serializ|visualiz|utiliz|personaliz|standardiz)\\w*)\\b",
				Pattern.CASE_INSENSITIVE);
		Properties en = load("messages.properties");
		for (String key : en.stringPropertyNames())
		{
			Matcher m = american.matcher(en.getProperty(key));
			assertTrue(!m.find(), key + " uses American spelling: " + (m.find(0) ? m.group() : ""));
		}
		assertTrue(en.getProperty("about.text").contains("Licence"));
	}

	private static Properties load(String name) throws IOException
	{
		Properties p = new Properties();
		try (InputStream in = UiLogicTest.class.getResourceAsStream("/yact/ui/" + name);
				var reader = new java.io.InputStreamReader(in, java.nio.charset.StandardCharsets.UTF_8))
		{
			p.load(reader);
		}
		return p;
	}

	/** String literals that look like message keys, plus the keys built from enum names. */
	private static Set<String> usedKeys() throws IOException
	{
		Pattern literal = Pattern.compile("\"((?:about|access|action|app|button|column|conflict|create|delete|error|filter|full|grow|"
				+ "job|key|keypair|kdf|label|menu|problem|protect|quit|rename|selftest|slot|start|status|unlock|view|wipe)\\.[A-Za-z.]+)\"");
		Set<String> keys = new TreeSet<>();
		try (Stream<Path> files = Files.walk(Path.of("src/main/java")))
		{
			for (Path f : files.filter(p -> p.toString().endsWith(".java")).toList())
			{
				Matcher m = literal.matcher(Files.readString(f));
				while (m.find())
					keys.add(m.group(1));
			}
		}
		for (PasswordRating r : PasswordRating.values())
			keys.add("password." + r.name());
		for (yact.core.crypto.CipherSuite s : yact.core.crypto.CipherSuite.values())
			keys.add("cipher." + s.name());
		return keys;
	}
}
