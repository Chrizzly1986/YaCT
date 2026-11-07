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
		assertEquals(PasswordRating.WEAK, PasswordRating.of("abcdefgh"));
		assertEquals(PasswordRating.OK, PasswordRating.of("abcdefgh12"));
		assertEquals(PasswordRating.STRONG, PasswordRating.of("Abcdefgh1234"));
		assertEquals(PasswordRating.STRONG, PasswordRating.of("correct horse battery"));
		assertEquals(PasswordRating.TOO_SHORT, PasswordRating.of("🔒🔒🔒🔒"),
				"counts code points, not chars");
	}

	/** Every key the code uses exists in every language, and every text is a valid message pattern. */
	@Test
	void messagesAreComplete() throws IOException
	{
		Properties en = load("messages.properties");
		Properties de = load("messages_de.properties");
		assertEquals(new TreeSet<>(en.stringPropertyNames()), new TreeSet<>(de.stringPropertyNames()),
				"both languages have the same keys");

		Set<String> used = usedKeys();
		assertTrue(used.size() > 100, "found " + used.size() + " keys");
		Set<String> missing = new TreeSet<>(used);
		missing.removeAll(en.stringPropertyNames());
		assertEquals(Set.of(), missing, "keys used in the code but missing from the bundles");

		for (Properties p : new Properties[] { en, de })
			for (String key : p.stringPropertyNames())
			{
				String text = p.getProperty(key);
				if (text.contains("{0}"))
				{
					String formatted = new MessageFormat(text).format(new Object[] { "A", "B", "C", "D" });
					assertTrue(!formatted.contains("{"), key + " has an unbalanced quote: " + formatted);
				}
			}
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
