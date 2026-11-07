/*******************************************************************************
 * YaCT | (c) 2015-2026 Christian Hoppe | http://opensource.org/licenses/MIT
 ******************************************************************************/
package yact.ui;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import yact.core.codec.FormatException;
import yact.core.pq.HybridPublicKey;

/** Reading and writing key files. */
final class KeyIO
{
	private static final long MAX_KEY_FILE = 64 * 1024;

	private KeyIO()
	{
	}

	/** Reads a public key in text form, or in binary form as a fallback. */
	static HybridPublicKey readPublicKey(Path p) throws IOException
	{
		byte[] data = readSmall(p);
		String text = new String(data, StandardCharsets.US_ASCII);
		return text.contains("-----BEGIN YACT PUBLIC KEY-----") ? HybridPublicKey.fromArmored(text)
				: HybridPublicKey.decode(data);
	}

	static byte[] readSmall(Path p) throws IOException
	{
		if (Files.size(p) > MAX_KEY_FILE)
			throw new FormatException("file is too large for a key file");
		return Files.readAllBytes(p);
	}
}
