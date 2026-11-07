/*******************************************************************************
 * YaCT | (c) 2015-2026 Christian Hoppe | http://opensource.org/licenses/MIT
 ******************************************************************************/
package yact.ui;

import java.text.NumberFormat;

/** Formats and parses sizes. Units are binary (1 KB = 1024 bytes), as most file managers show them. */
final class Sizes
{
	enum Unit
	{
		MB(1L << 20), GB(1L << 30), TB(1L << 40);

		final long factor;

		Unit(long factor)
		{
			this.factor = factor;
		}
	}

	/** Shows units in the user's language, e.g. "Go" in French. */
	static javafx.util.StringConverter<Unit> unitConverter()
	{
		return Dialogs.converter(u -> Messages.get("unit." + u.name()));
	}

	private Sizes()
	{
	}

	static String format(long bytes)
	{
		if (bytes < 1024)
			return bytes + " " + Messages.get("unit.B");
		String[] units = { "KB", "MB", "GB", "TB", "PB" };
		double v = bytes;
		int u = -1;
		while (v >= 1024 && u < units.length - 1)
		{
			v /= 1024;
			u++;
		}
		NumberFormat nf = NumberFormat.getNumberInstance(Messages.locale());
		nf.setMaximumFractionDigits(v < 10 ? 1 : 0);
		nf.setMinimumFractionDigits(0);
		return nf.format(v) + " " + Messages.get("unit." + units[u]);
	}

	/**
	 * Parses a number such as "1,5" or "1.5" (both separators accepted) in the given unit.
	 *
	 * @return the size in bytes, or -1 if the text is not a positive number
	 */
	static long parse(String text, Unit unit)
	{
		String t = text.trim().replace(',', '.');
		if (!t.matches("\\d{1,9}(\\.\\d{1,6})?"))
			return -1;
		double v = Double.parseDouble(t);
		if (v <= 0)
			return -1;
		double bytes = v * unit.factor;
		return bytes > Long.MAX_VALUE / 2 ? -1 : (long) bytes;
	}
}
