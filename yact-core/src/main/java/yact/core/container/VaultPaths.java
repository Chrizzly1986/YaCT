/*******************************************************************************
 * YaCT | (c) 2015-2026 Christian Hoppe | http://opensource.org/licenses/MIT
 ******************************************************************************/
package yact.core.container;

import java.nio.charset.StandardCharsets;
import java.text.Normalizer;

/**
 * Rules for paths inside a container.
 *
 * <p>A path is relative, uses {@code /} as separator, is in Unicode NFC, and
 * has no empty, {@code .} or {@code ..} segments and no control characters.
 * These rules make it impossible for a container to write outside the
 * target directory on extraction ("zip slip").
 *
 * <p>Because containers move between systems, the Windows rules apply
 * everywhere: no {@code < > : " | ? *} (a colon would write into an NTFS
 * alternate data stream), no device names such as {@code CON}, {@code NUL} or
 * {@code COM1} (also with an extension), no segment ending in a dot or space,
 * and at most 255 UTF-8 bytes per segment.
 */
public final class VaultPaths
{
	public static final int MAX_LENGTH = 4096; // UTF-8 bytes
	public static final int MAX_SEGMENT_LENGTH = 255; // UTF-8 bytes
	private static final String FORBIDDEN = "<>:\"|?*\\";
	private static final java.util.regex.Pattern DEVICE = java.util.regex.Pattern.compile(
			"(?i)(con|prn|aux|nul|conin\\$|conout\\$|(com|lpt)[0-9\u00b9\u00b2\u00b3])(\\..*)?");

	private VaultPaths()
	{
	}

	/**
	 * Normalises a user-supplied path: backslashes become slashes, leading and
	 * trailing slashes are removed, and the result is checked against the rules.
	 *
	 * @throws IllegalArgumentException if the path is not acceptable
	 */
	public static String normalize(String path)
	{
		String p = Normalizer.normalize(path, Normalizer.Form.NFC).replace('\\', '/');
		while (p.startsWith("/"))
			p = p.substring(1);
		while (p.endsWith("/"))
			p = p.substring(0, p.length() - 1);
		check(p);
		return p;
	}

	/** Case-folded form, to detect paths that are the same file on Windows and macOS. */
	static String fold(String path)
	{
		return path.toUpperCase(java.util.Locale.ROOT).toLowerCase(java.util.Locale.ROOT);
	}

	/** Normalises a directory prefix; the empty string means the root. */
	static String normalizeDirectory(String dir)
	{
		String d = Normalizer.normalize(dir, Normalizer.Form.NFC).replace('\\', '/');
		while (d.startsWith("/"))
			d = d.substring(1);
		while (d.endsWith("/"))
			d = d.substring(0, d.length() - 1);
		if (!d.isEmpty())
			check(d);
		return d;
	}

	/** True if {@code path} is {@code dir} itself or lies below it; every path lies below the root "". */
	static boolean isWithin(String path, String dir)
	{
		return dir.isEmpty() || path.equals(dir) || path.startsWith(dir + "/");
	}

	static String join(String dir, String name)
	{
		return dir.isEmpty() ? name : dir + "/" + name;
	}

	/** Throws unless {@code p} is already a valid, normalised path. */
	static void check(String p)
	{
		if (p.isEmpty())
			throw new IllegalArgumentException("path is empty");
		if (p.getBytes(StandardCharsets.UTF_8).length > MAX_LENGTH)
			throw new IllegalArgumentException("path is too long");
		if (!Normalizer.isNormalized(p, Normalizer.Form.NFC))
			throw new IllegalArgumentException("path is not in Unicode NFC");
		for (String segment : p.split("/", -1))
		{
			if (segment.isEmpty() || segment.equals(".") || segment.equals(".."))
				throw new IllegalArgumentException("invalid path segment in: " + p);
			if (segment.getBytes(StandardCharsets.UTF_8).length > MAX_SEGMENT_LENGTH)
				throw new IllegalArgumentException("file or folder name is too long: " + segment);
			for (int i = 0; i < segment.length(); i++)
			{
				char c = segment.charAt(i);
				if (Character.isISOControl(c) || FORBIDDEN.indexOf(c) >= 0)
					throw new IllegalArgumentException("invalid character '" + c + "' in path: " + p);
			}
			char last = segment.charAt(segment.length() - 1);
			if (last == '.' || last == ' ')
				throw new IllegalArgumentException("name must not end with a dot or space: " + segment);
			if (DEVICE.matcher(segment).matches())
				throw new IllegalArgumentException("reserved device name: " + segment);
		}
	}
}
