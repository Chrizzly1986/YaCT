/*******************************************************************************
 * YaCT | (c) 2015-2026 Christian Hoppe | http://opensource.org/licenses/MIT
 ******************************************************************************/
package yact.ui;

import java.time.Month;
import java.time.format.TextStyle;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import yact.core.crypto.CryptoCapabilities;

/**
 * Entry point for a plain {@code java -cp ...} start and for packaged builds.
 * JavaFX refuses to start an {@code Application} subclass directly from the
 * class path, so this class, which is not one, launches it.
 *
 * <p>{@code --self-test} checks the runtime without a display and exits with
 * 0 or 1; packaged builds are smoke-tested with it.
 */
public final class Launcher
{
	private Launcher()
	{
	}

	public static void main(String[] args)
	{
		if (args.length > 0 && args[0].equals("--self-test"))
			System.exit(selfTest() ? 0 : 1);
		if (args.length > 0 && args[0].equals("--version"))
		{
			System.out.println("YaCT " + YactApp.VERSION);
			return;
		}
		javafx.application.Application.launch(YactApp.class, args);
	}

	/** Crypto primitives, and locale data for every translated language. */
	static boolean selfTest()
	{
		System.out.println("YaCT " + YactApp.VERSION + ", Java " + Runtime.version());
		List<CryptoCapabilities.Capability> caps = CryptoCapabilities.check();
		for (CryptoCapabilities.Capability c : caps)
			System.out.printf("  [%s] %-20s %s%n", c.available() ? " OK " : "FAIL", c.name(), c.detail());

		// A runtime without jdk.localedata only knows English formats.
		Map<String, String> october = Map.of("de", "Oktober", "fr", "octobre", "es", "octubre", "pt", "outubro");
		boolean locales = october.keySet().containsAll(Messages.TRANSLATED);
		for (String lang : Messages.TRANSLATED)
		{
			String month = Month.OCTOBER.getDisplayName(TextStyle.FULL, Locale.forLanguageTag(lang));
			boolean ok = month.equals(october.get(lang));
			locales &= ok;
			System.out.printf("  [%s] locale %-13s %s%n", ok ? " OK " : "FAIL", lang, month);
		}
		boolean all = CryptoCapabilities.allAvailable(caps) && locales;
		System.out.println(all ? "All checks passed." : "Some checks FAILED.");
		return all;
	}
}
