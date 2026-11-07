/*******************************************************************************
 * YaCT | (c) 2015-2026 Christian Hoppe | http://opensource.org/licenses/MIT
 ******************************************************************************/
package yact.ui;

import java.text.MessageFormat;
import java.util.List;
import java.util.Locale;
import java.util.MissingResourceException;
import java.util.ResourceBundle;

/**
 * User-visible texts, from {@code yact/ui/messages*.properties}.
 *
 * <p>German, French, Spanish and (European) Portuguese follow the system
 * language. Every other language, including US English, gets the British
 * English texts and British formats for dates and numbers.
 */
final class Messages
{
	/** Languages with their own translation; all others use British English. */
	static final List<String> TRANSLATED = List.of("de", "fr", "es", "pt");

	private static final Locale LOCALE = effective(Locale.getDefault());

	/** No fallback to the system locale: an untranslated language must end up in the British base bundle. */
	private static final ResourceBundle BUNDLE = ResourceBundle.getBundle("yact.ui.messages", LOCALE,
			ResourceBundle.Control.getNoFallbackControl(ResourceBundle.Control.FORMAT_PROPERTIES));

	/** The locale for texts and formats, given the system locale. */
	static Locale effective(Locale system)
	{
		return TRANSLATED.contains(system.getLanguage()) ? system : Locale.UK;
	}

	/** Locale for formatting dates and numbers. */
	static Locale locale()
	{
		return LOCALE;
	}

	private Messages()
	{
	}

	/** The text for {@code key}, with {@code {0}}-style placeholders filled in. */
	static String get(String key, Object... args)
	{
		String pattern;
		try
		{
			pattern = BUNDLE.getString(key);
		}
		catch (MissingResourceException e)
		{
			return "!" + key + "!";
		}
		return args.length == 0 ? pattern : new MessageFormat(pattern, LOCALE).format(args);
	}
}
