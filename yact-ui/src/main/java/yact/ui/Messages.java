/*******************************************************************************
 * YaCT | (c) 2015-2026 Christian Hoppe | http://opensource.org/licenses/MIT
 ******************************************************************************/
package yact.ui;

import java.text.MessageFormat;
import java.util.Locale;
import java.util.MissingResourceException;
import java.util.ResourceBundle;

/** User-visible texts, from {@code yact/ui/messages*.properties}; German or English by system language. */
final class Messages
{
	private static final ResourceBundle BUNDLE = ResourceBundle.getBundle("yact.ui.messages", Locale.getDefault());

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
		return args.length == 0 ? pattern : new MessageFormat(pattern, BUNDLE.getLocale()).format(args);
	}
}
