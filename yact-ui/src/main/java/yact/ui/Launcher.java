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
		// Before anything else: is foreign code being injected into this process?
		List<String> injected = RuntimeChecks.current();
		boolean packaged = Boolean.getBoolean("yact.packaged");
		boolean override = RuntimeChecks.developerOverride(
				java.lang.management.ManagementFactory.getRuntimeMXBean().getInputArguments(), packaged);
		if (!injected.isEmpty() && !override)
		{
			System.err.println("YaCT refuses to start: code could be injected into the process through");
			injected.forEach(p -> System.err.println("  - " + p));
			if (args.length > 0 && args[0].startsWith("--"))
				System.exit(2);
			YactApp.refuseToStart(injected);
		}
		if (args.length > 0 && args[0].equals("--self-test"))
			System.exit(selfTest() ? 0 : 1);
		if (args.length > 0 && args[0].equals("--version"))
		{
			System.out.println("YaCT " + YactApp.VERSION);
			return;
		}
		javafx.application.Application.launch(YactApp.class, args);
	}

	/**
	 * Crypto primitives, locale data for every translated language, and the installation part of the
	 * security check (the same as Help → Security check). Fails on anything critical.
	 */
	static boolean selfTest()
	{
		System.out.println("YaCT " + YactApp.VERSION + ", Java " + Runtime.version());
		SecurityCheck.Environment env = SecurityCheck.environment();
		List<CryptoCapabilities.Capability> caps = env.crypto();
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
		boolean critical = false;
		for (SecurityCheck.Finding f : SecurityCheck.evaluate(env))
		{
			critical |= f.level() == SecurityCheck.Level.CRITICAL;
			System.out.printf("  [%s] %s%n", switch (f.level())
			{
				case OK -> " OK ";
				case INFO -> "NOTE";
				case WARNING -> "WARN";
				case CRITICAL -> "FAIL";
			}, f.text());
		}
		boolean all = CryptoCapabilities.allAvailable(caps) && locales && !critical;
		System.out.println(all ? "All checks passed." : "Some checks FAILED.");
		return all;
	}
}
