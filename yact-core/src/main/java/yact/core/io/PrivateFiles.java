/*******************************************************************************
 * YaCT | (c) 2015-2026 Christian Hoppe | http://opensource.org/licenses/MIT
 ******************************************************************************/
package yact.core.io;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.OpenOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.FileAttribute;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.HexFormat;

import yact.core.crypto.JdkCrypto;

/**
 * Files only the current user may read: containers and private key files.
 *
 * <p>On POSIX systems they are created with permissions {@code rw-------}
 * from the start (not changed afterwards, which would leave a window). On
 * Windows the file inherits the ACL of its folder; inside the user's profile
 * that is private to the user.
 */
public final class PrivateFiles
{
	private static final boolean POSIX = FileSystems.getDefault().supportedFileAttributeViews().contains("posix");

	private PrivateFiles()
	{
	}

	/** Attributes for creating a private file, or none where POSIX permissions are not supported. */
	public static FileAttribute<?>[] attributes()
	{
		return POSIX ? new FileAttribute<?>[] { PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")) }
				: new FileAttribute<?>[0];
	}

	/** Opens a new private file; fails if it exists. */
	public static FileChannel createNew(Path file, OpenOption... extra) throws IOException
	{
		java.util.Set<OpenOption> options = new java.util.HashSet<>(java.util.List.of(extra));
		options.add(StandardOpenOption.CREATE_NEW);
		options.add(StandardOpenOption.WRITE);
		return FileChannel.open(file, options, attributes());
	}

	/**
	 * Writes {@code data} to {@code target} atomically: into a private temporary
	 * file next to it, forced to disk, then moved into place (replacing an
	 * existing file). A crash leaves either the old file or the complete new one.
	 */
	public static void writeAtomically(Path target, byte[] data) throws IOException
	{
		Path dir = target.toAbsolutePath().getParent();
		Path tmp = dir.resolve("." + target.getFileName() + "." + HexFormat.of().formatHex(JdkCrypto.randomBytes(6)) + ".tmp");
		try
		{
			try (FileChannel ch = createNew(tmp))
			{
				ByteBuffer buf = ByteBuffer.wrap(data);
				while (buf.hasRemaining())
					ch.write(buf);
				ch.force(true);
			}
			Files.move(tmp, target, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
		}
		finally
		{
			Files.deleteIfExists(tmp);
		}
	}
}
