/*******************************************************************************
 * YaCT | (c) 2015-2026 Christian Hoppe | http://opensource.org/licenses/MIT
 ******************************************************************************/
package yact.core.container;

import java.io.Closeable;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.charset.StandardCharsets;
import java.nio.file.DirectoryStream;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.FileTime;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.TreeMap;

import yact.core.codec.FormatException;
import yact.core.crypto.Argon2Params;
import yact.core.crypto.CipherSuite;
import yact.core.crypto.Passwords;
import yact.core.crypto.SelfTest;
import yact.core.format.ContainerFormatException;
import yact.core.format.ContainerHeader;
import yact.core.format.IntegrityException;
import yact.core.format.InvalidCredentialsException;
import yact.core.format.UnlockedHeader;
import yact.core.pq.HybridKeyPair;
import yact.core.pq.HybridPublicKey;
import yact.core.stream.ChunkedAeadInputStream;
import yact.core.stream.ChunkedAeadOutputStream;

/**
 * An open YaCT container: an encrypted file vault of fixed size.
 *
 * <p>File layout:
 * <pre>
 * 0          header copy A (64 KiB)
 * 65536      header copy B (64 KiB)
 * 131072     superblock slot 0 (4 KiB)
 * 135168     superblock slot 1 (4 KiB)
 * 139264     data area up to the end of the file
 * </pre>
 *
 * <p><b>Size.</b> A container has the size chosen at creation; {@link #grow}
 * enlarges it. Free space is filled with random data that looks like
 * ciphertext, so the file does not reveal how much is stored. File contents
 * go into free space and may be fragmented. A small reserve is always kept
 * for the index, so that deleting stays possible in a full container.
 *
 * <p><b>Crash safety.</b> New contents and the new index are only written to
 * space the committed state does not use. {@link #commit()} forces them to
 * disk, then writes the other superblock slot; until then the previous state
 * is current. Header changes (key slots) write copy B, then copy A; opening
 * repairs a copy that differs.
 *
 * <p><b>Deleting.</b> With {@link #setWipeOnDelete(boolean) wipe on delete}
 * (the default), space that a commit frees — deleted and replaced files and
 * old index versions — is overwritten with random data right after that
 * commit, so it cannot be recovered even with the key. Copies kept elsewhere
 * by the file system, snapshots, backups, sync services or an SSD's wear
 * levelling are out of reach of any program.
 *
 * <p>Changes are buffered in memory until {@link #commit()} or
 * {@link #close()}. Instances are not thread-safe; the file is locked against
 * other opens while in use.
 */
public final class Container implements Closeable
{
	static final long HEADER_B_OFFSET = ContainerHeader.AREA_SIZE;
	static final long SUPERBLOCK_OFFSET = 2L * ContainerHeader.AREA_SIZE;
	static final long DATA_OFFSET = SUPERBLOCK_OFFSET + 2L * Superblock.SIZE;

	/** Smallest container that can be created. */
	public static final long MIN_SIZE = 1L << 20;

	/** Kept free beyond the current index size, for index growth through renames and new extents. */
	private static final long INDEX_MARGIN = 64 * 1024;

	private static final byte[] FILE_AAD = "YaCT v1 file".getBytes(StandardCharsets.US_ASCII);
	private static final byte[] INDEX_AAD = "YaCT v1 index".getBytes(StandardCharsets.US_ASCII);
	private static final SecureRandom RANDOM = yact.core.crypto.JdkCrypto.random();

	/** Opens a key slot; implemented by password and private key. */
	@FunctionalInterface
	private interface Unlocker
	{
		UnlockedHeader unlock(ContainerHeader header) throws InvalidCredentialsException, IntegrityException;
	}

	private final Path file;
	private final FileChannel channel;
	private final FileLock lock;
	private final UnlockedHeader keys;
	private long size;
	private TreeMap<String, Index.Item> items;
	/** Bytes the encoded index currently needs. */
	private long indexBytes;
	/**
	 * Space that must not be overwritten: everything the committed state
	 * references, plus contents written since the last commit.
	 */
	private ExtentSet allocated;
	private Superblock current;
	private boolean wipeOnDelete = true;
	private boolean dirty;
	private boolean closed;

	private Container(Path file, FileChannel channel, FileLock lock, UnlockedHeader keys)
	{
		this.file = file;
		this.channel = channel;
		this.lock = lock;
		this.keys = keys;
	}

	// ================================================================== create / open

	/**
	 * Creates a new, empty container protected by a password. Fails if {@code file} exists.
	 *
	 * @param size     total file size in bytes, at least {@link #MIN_SIZE}
	 * @param progress reports filling the container with random data, which takes most of the time
	 */
	public static Container create(Path file, CipherSuite suite, char[] password, Argon2Params params, long size,
			ProgressListener progress) throws IOException
	{
		checkSize(size);
		SelfTest.require(); // before the password is processed
		return create(file, UnlockedHeader.create(suite, ContainerHeader.DEFAULT_CHUNK_EXPONENT, password, params), size,
				progress);
	}

	/** Creates a new, empty container that only the owner of {@code recipient}'s private key can open. */
	public static Container create(Path file, CipherSuite suite, HybridPublicKey recipient, long size,
			ProgressListener progress) throws IOException
	{
		checkSize(size);
		SelfTest.require();
		return create(file, UnlockedHeader.create(suite, ContainerHeader.DEFAULT_CHUNK_EXPONENT, recipient), size,
				progress);
	}

	private static void checkSize(long size)
	{
		if (size < MIN_SIZE)
			throw new IllegalArgumentException("a container must be at least " + MIN_SIZE + " bytes");
	}

	private static Container create(Path file, UnlockedHeader keys, long size, ProgressListener progress)
			throws IOException
	{
		SelfTest.require();
		FileChannel ch;
		try
		{
			ch = FileChannel.open(file, StandardOpenOption.CREATE_NEW, StandardOpenOption.READ, StandardOpenOption.WRITE);
		}
		catch (IOException e)
		{
			keys.close();
			throw e;
		}
		try
		{
			FileLock lock = lockOrFail(ch);
			Container c = new Container(file, ch, lock, keys);
			c.writeHeaderCopies();
			ch.write(ByteBuffer.allocate(2 * Superblock.SIZE), SUPERBLOCK_OFFSET);
			RandomFill.fill(ch, List.of(new Extent(DATA_OFFSET, size - DATA_OFFSET)), progress);
			c.size = size;
			c.items = new TreeMap<>();
			c.indexBytes = 4;
			c.allocated = new ExtentSet();
			c.current = new Superblock(0, new byte[Superblock.SALT_LENGTH], List.of());
			c.dirty = true;
			c.commit();
			return c;
		}
		catch (IOException | RuntimeException e)
		{
			keys.close();
			ch.close();
			Files.deleteIfExists(file);
			throw e;
		}
	}

	/**
	 * Opens a container with a password.
	 *
	 * @throws InvalidCredentialsException if the password is wrong
	 * @throws IntegrityException          if the container was modified or damaged
	 * @throws ContainerFormatException    if the file is not a YaCT container
	 */
	public static Container open(Path file, char[] password) throws IOException, InvalidCredentialsException
	{
		return open(file, h -> h.unlock(password));
	}

	/** Opens a container with a private key. Exceptions as for {@link #open(Path, char[])}. */
	public static Container open(Path file, HybridKeyPair key) throws IOException, InvalidCredentialsException
	{
		return open(file, h -> h.unlock(key));
	}

	private static Container open(Path file, Unlocker unlocker) throws IOException, InvalidCredentialsException
	{
		SelfTest.require();
		FileChannel ch = FileChannel.open(file, StandardOpenOption.READ, StandardOpenOption.WRITE);
		try
		{
			FileLock lock = lockOrFail(ch);
			if (ch.size() < ContainerHeader.AREA_SIZE)
				throw new ContainerFormatException("file too short for a YaCT container");

			byte[] areaA = ChannelIO.readFully(ch, 0, ContainerHeader.AREA_SIZE);
			byte[] areaB = ChannelIO.readFully(ch, HEADER_B_OFFSET, ContainerHeader.AREA_SIZE);
			UnlockedHeader keys = unlockEither(areaA, areaB, unlocker);

			Container c = new Container(file, ch, lock, keys);
			try
			{
				c.size = ch.size();
				if (c.size < DATA_OFFSET)
					throw new IntegrityException("container file is truncated");
				c.repairHeaderCopies(areaA, areaB);
				c.loadIndex();
				return c;
			}
			catch (IOException | RuntimeException e)
			{
				keys.close();
				throw e;
			}
		}
		catch (IOException | InvalidCredentialsException | RuntimeException e)
		{
			ch.close();
			throw e;
		}
	}

	/** Tries header copy A, then B (unless identical). An integrity error outranks a wrong password. */
	private static UnlockedHeader unlockEither(byte[] areaA, byte[] areaB, Unlocker unlocker)
			throws IOException, InvalidCredentialsException
	{
		Exception failureA;
		try
		{
			return unlocker.unlock(ContainerHeader.parse(areaA));
		}
		catch (ContainerFormatException | InvalidCredentialsException | IntegrityException e)
		{
			failureA = e;
		}
		Exception failure = failureA;
		if (!Arrays.equals(areaA, areaB))
		{
			try
			{
				return unlocker.unlock(ContainerHeader.parse(areaB));
			}
			catch (ContainerFormatException | InvalidCredentialsException | IntegrityException failureB)
			{
				failure = worse(failureA, failureB);
			}
		}
		if (failure instanceof InvalidCredentialsException ic)
			throw ic;
		throw (IOException) failure;
	}

	/** Integrity error, then wrong credentials, then format error. */
	private static Exception worse(Exception a, Exception b)
	{
		for (Class<?> c : List.of(IntegrityException.class, InvalidCredentialsException.class))
		{
			if (c.isInstance(a))
				return a;
			if (c.isInstance(b))
				return b;
		}
		return a;
	}

	private static FileLock lockOrFail(FileChannel ch) throws IOException
	{
		FileLock lock;
		try
		{
			lock = ch.tryLock();
		}
		catch (java.nio.channels.OverlappingFileLockException e)
		{
			lock = null; // already open in this JVM
		}
		if (lock == null)
			throw new IOException("container is already open");
		return lock;
	}

	// ================================================================== reading

	/** All files, sorted by path. */
	public List<ContainerEntry> list()
	{
		checkOpen();
		return items.values().stream().map(Index.Item::entry).toList();
	}

	/** Files directly or indirectly below {@code directory} ("" for all), sorted by path. */
	public List<ContainerEntry> list(String directory)
	{
		checkOpen();
		String dir = VaultPaths.normalizeDirectory(directory);
		return items.values().stream().map(Index.Item::entry).filter(e -> VaultPaths.isWithin(e.path(), dir)).toList();
	}

	public Optional<ContainerEntry> entry(String path)
	{
		checkOpen();
		Index.Item it = items.get(VaultPaths.normalize(path));
		return it == null ? Optional.empty() : Optional.of(it.entry());
	}

	/**
	 * Opens a file for reading. The stream fails with {@link IntegrityException}
	 * if the content was modified; data is only complete once it returns -1.
	 * Do not modify the container while the stream is open.
	 */
	public InputStream read(String path) throws IOException
	{
		checkOpen();
		Index.Item it = items.get(VaultPaths.normalize(path));
		if (it == null)
			throw new NoSuchFileException(path);
		return verifiedSize(openStream(it.salt(), it.extents(), FILE_AAD), it.entry().size());
	}

	/**
	 * Decrypts one file to {@code target}. The content is written to a
	 * temporary file next to the target and only moved into place once it
	 * has been fully verified, so no partial file is left behind.
	 */
	public void extract(String path, Path target, boolean overwrite) throws IOException
	{
		extract(path, target, overwrite, ProgressListener.NONE);
	}

	/** As {@link #extract(String, Path, boolean)}, reporting the bytes decrypted so far. */
	public void extract(String path, Path target, boolean overwrite, ProgressListener progress) throws IOException
	{
		checkOpen();
		String p = VaultPaths.normalize(path);
		Index.Item it = items.get(p);
		if (it == null)
			throw new NoSuchFileException(path);
		if (!overwrite && Files.exists(target, LinkOption.NOFOLLOW_LINKS))
			throw new FileAlreadyExistsException(target.toString());

		Path dir = target.toAbsolutePath().getParent();
		Files.createDirectories(dir);
		Path tmp = Files.createTempFile(dir, ".yact-", ".part");
		try
		{
			try (InputStream in = counting(read(p), it.entry().size(), progress); OutputStream out = Files.newOutputStream(tmp))
			{
				in.transferTo(out);
			}
			Files.setLastModifiedTime(tmp, FileTime.from(it.entry().modified()));
			if (overwrite)
				Files.move(tmp, target, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
			else
				Files.move(tmp, target); // fails if the target appeared in the meantime
		}
		finally
		{
			Files.deleteIfExists(tmp);
		}
	}

	/**
	 * Decrypts all files below {@code directory} ("" for all) into
	 * {@code targetDir}, keeping their relative paths.
	 */
	public void extractAll(String directory, Path targetDir, boolean overwrite) throws IOException
	{
		checkOpen();
		Path base = targetDir.toAbsolutePath().normalize();
		String dir = VaultPaths.normalizeDirectory(directory);
		for (ContainerEntry e : list(dir))
		{
			String relative = dir.isEmpty() ? e.path() : e.path().substring(dir.length() + 1);
			Path target = base.resolve(relative.replace('/', base.getFileSystem().getSeparator().charAt(0))).normalize();
			// Paths are validated on read and on add; this is a second line of defence.
			if (!target.startsWith(base))
				throw new IOException("refusing to write outside the target directory: " + e.path());
			extract(e.path(), target, overwrite);
		}
	}

	// ================================================================== writing

	/**
	 * Adds a file from a stream.
	 *
	 * @param overwrite replace an existing file at the same path
	 * @throws FileAlreadyExistsException if the path exists and {@code overwrite} is false
	 * @throws ContainerFullException     if the content does not fit; the container is unchanged
	 * @throws IllegalArgumentException   if the path is invalid, or a file and a directory would share a name
	 */
	public void add(String path, InputStream content, Instant modified, boolean overwrite) throws IOException
	{
		add(path, content, modified, overwrite, -1);
	}

	private void add(String path, InputStream content, Instant modified, boolean overwrite, long sizeHint)
			throws IOException
	{
		checkOpen();
		String p = VaultPaths.normalize(path);
		if (items.containsKey(p) && !overwrite)
			throw new FileAlreadyExistsException(p);
		checkNoFileDirectoryClash(p);
		if (sizeHint >= 0 && sealedSize(sizeHint) > freeBytes())
			throw new ContainerFullException("not enough space for " + p, freeBytes());

		byte[] salt = new byte[Superblock.SALT_LENGTH];
		RANDOM.nextBytes(salt);
		int entryBase = 2 + p.getBytes(StandardCharsets.UTF_8).length + 8 + 8 + 16 + 4;
		ExtentWriter raw = new ExtentWriter(entryBase, sizeHint < 0 ? -1 : sealedSize(sizeHint));
		long plainSize;
		byte[] key = keys.streamKey(salt);
		try
		{
			ChunkedAeadOutputStream enc = new ChunkedAeadOutputStream(raw, keys.header().cipherSuite(), key, FILE_AAD,
					keys.header().chunkSize());
			plainSize = content.transferTo(enc);
			enc.finish();
		}
		catch (IOException | RuntimeException e)
		{
			raw.abort();
			throw e;
		}
		finally
		{
			Passwords.wipe(key);
		}
		putItem(new Index.Item(new ContainerEntry(p, plainSize, modified), salt, raw.finish()));
	}

	/**
	 * Imports a file, or a directory tree, from disk into {@code targetDirectory}
	 * ("" for the root). Symbolic links are skipped and never followed.
	 *
	 * @throws ContainerFullException if a file does not fit; files imported before it stay added
	 */
	public void importPath(Path source, String targetDirectory, boolean overwrite) throws IOException
	{
		checkOpen();
		String dir = VaultPaths.normalizeDirectory(targetDirectory);
		String name = source.toAbsolutePath().normalize().getFileName().toString();
		importRecursive(source, VaultPaths.join(dir, name), overwrite);
	}

	private void importRecursive(Path source, String target, boolean overwrite) throws IOException
	{
		if (Files.isSymbolicLink(source))
			return;
		if (Files.isDirectory(source, LinkOption.NOFOLLOW_LINKS))
		{
			try (DirectoryStream<Path> children = Files.newDirectoryStream(source))
			{
				for (Path child : children)
					importRecursive(child, target + "/" + child.getFileName(), overwrite);
			}
		}
		else if (Files.isRegularFile(source, LinkOption.NOFOLLOW_LINKS))
		{
			Instant modified = Files.getLastModifiedTime(source, LinkOption.NOFOLLOW_LINKS).toInstant();
			try (InputStream in = Files.newInputStream(source, LinkOption.NOFOLLOW_LINKS))
			{
				add(target, in, modified, overwrite, Files.size(source));
			}
		}
	}

	/**
	 * Imports one regular file from disk to {@code targetPath}, reporting the
	 * bytes read so far. Symbolic links are rejected.
	 *
	 * @throws FileAlreadyExistsException if the path exists and {@code overwrite} is false
	 * @throws ContainerFullException     if the file does not fit; the container is unchanged
	 */
	public void importFile(Path source, String targetPath, boolean overwrite, ProgressListener progress)
			throws IOException
	{
		checkOpen();
		if (!Files.isRegularFile(source, LinkOption.NOFOLLOW_LINKS))
			throw new IOException("not a regular file: " + source);
		long size = Files.size(source);
		Instant modified = Files.getLastModifiedTime(source, LinkOption.NOFOLLOW_LINKS).toInstant();
		try (InputStream in = counting(Files.newInputStream(source, LinkOption.NOFOLLOW_LINKS), size, progress))
		{
			add(targetPath, in, modified, overwrite, size);
		}
	}

	/** Deletes one file. Its space is freed, and wiped if enabled, by the next {@link #commit()}. */
	public void delete(String path) throws IOException
	{
		checkOpen();
		String p = VaultPaths.normalize(path);
		if (!items.containsKey(p))
			throw new NoSuchFileException(path);
		removeItem(p);
	}

	/** Deletes all files below {@code directory}; returns how many. Space is freed as for {@link #delete}. */
	public int deleteDirectory(String directory)
	{
		checkOpen();
		String dir = VaultPaths.normalize(directory);
		List<String> doomed = items.keySet().stream().filter(p -> VaultPaths.isWithin(p, dir)).toList();
		doomed.forEach(this::removeItem);
		return doomed.size();
	}

	/** Renames or moves a file. Only the index changes; the content is not rewritten. */
	public void rename(String from, String to) throws IOException
	{
		checkOpen();
		String f = VaultPaths.normalize(from);
		String t = VaultPaths.normalize(to);
		Index.Item it = items.get(f);
		if (it == null)
			throw new NoSuchFileException(from);
		if (f.equals(t))
			return;
		if (items.containsKey(t))
			throw new FileAlreadyExistsException(t);
		removeItem(f);
		try
		{
			checkNoFileDirectoryClash(t);
		}
		catch (IllegalArgumentException e)
		{
			putItem(it);
			throw e;
		}
		putItem(it.withPath(t));
	}

	private void putItem(Index.Item it)
	{
		Index.Item old = items.put(it.entry().path(), it);
		if (old != null)
			indexBytes -= old.encodedSize();
		indexBytes += it.encodedSize();
		dirty = true;
	}

	private void removeItem(String path)
	{
		Index.Item old = items.remove(path);
		if (old != null)
		{
			indexBytes -= old.encodedSize();
			dirty = true;
		}
	}

	/** A file "a" and a file "a/b" cannot coexist: "a" would have to be both a file and a directory. */
	private void checkNoFileDirectoryClash(String p)
	{
		for (int i = p.indexOf('/'); i >= 0; i = p.indexOf('/', i + 1))
			if (items.containsKey(p.substring(0, i)))
				throw new IllegalArgumentException("'" + p.substring(0, i) + "' is a file, not a directory");
		String child = items.ceilingKey(p + "/");
		if (child != null && child.startsWith(p + "/"))
			throw new IllegalArgumentException("'" + p + "' is a directory");
	}

	/** True if there are changes that {@link #commit()} has not yet persisted. */
	public boolean hasUncommittedChanges()
	{
		return dirty;
	}

	/**
	 * Persists all changes: writes a new index into free space, forces data to
	 * disk, then switches the superblock. Afterwards, space no longer in use is
	 * freed and, with wipe on delete, overwritten. Does nothing if nothing changed.
	 *
	 * @throws ContainerFullException only if the reserve was exhausted, e.g. by very long paths;
	 *                                nothing is lost, the container can be enlarged and the commit repeated
	 */
	public void commit() throws IOException
	{
		checkOpen();
		if (!dirty)
			return;
		byte[] index = Index.encode(items);
		byte[] indexSalt = randomBytes(Superblock.SALT_LENGTH);
		List<Extent> target = claimForIndex(sealedSize(index.length));
		try
		{
			writeFixed(target, indexSalt, INDEX_AAD, index);
			channel.force(true);
		}
		catch (IOException | RuntimeException e)
		{
			target.forEach(allocated::remove);
			throw e;
		}

		Superblock next = new Superblock(current.generation() + 1, indexSalt, target);
		ChannelIO.writeFully(channel, next.encode(keys, RANDOM), SUPERBLOCK_OFFSET + (long) next.slot() * Superblock.SIZE);
		channel.force(true);
		current = next;
		dirty = false;

		ExtentSet live = liveExtents();
		ExtentSet freed = allocated.minus(live);
		allocated = live;
		if (wipeOnDelete && freed.total() > 0)
		{
			RandomFill.fill(channel, freed.extents(), ProgressListener.NONE);
			channel.force(true);
		}
	}

	/** Everything the current state references: file contents and the current index. */
	private ExtentSet liveExtents()
	{
		ExtentSet live = ExtentSet.of(current.indexExtents());
		for (Index.Item it : items.values())
			for (Extent e : it.extents())
				live.add(e);
		return live;
	}

	/** Largest gaps first, to keep the index in few extents. */
	private List<Extent> claimForIndex(long need) throws ContainerFullException
	{
		List<Extent> gaps = new ArrayList<>(allocated.gaps(DATA_OFFSET, size));
		gaps.sort((a, b) -> Long.compare(b.length(), a.length()));
		List<Extent> chosen = new ArrayList<>();
		long remaining = need;
		for (Extent g : gaps)
		{
			if (remaining == 0 || chosen.size() == Superblock.MAX_INDEX_EXTENTS)
				break;
			long n = Math.min(g.length(), remaining);
			chosen.add(new Extent(g.offset(), n));
			remaining -= n;
		}
		if (remaining > 0)
			throw new ContainerFullException("no space left for the index; enlarge the container", freeBytes());
		chosen.forEach(allocated::add);
		return chosen;
	}

	// ================================================================== size and space

	/** Total size of the container file in bytes. */
	public long size()
	{
		checkOpen();
		return size;
	}

	/** Bytes available for new encrypted content, after the index reserve. */
	public long freeBytes()
	{
		checkOpen();
		return Math.max(0, gapTotal() - reserve(0));
	}

	/**
	 * Plaintext size that still fits as one new file, allowing for its index
	 * entry (a path of up to 4096 bytes in up to 64 fragments). Slightly
	 * conservative; this is the figure to show the user.
	 */
	public long freeBytesForContent()
	{
		checkOpen();
		long free = Math.max(0, gapTotal() - reserve(4096 + 64 * 16 + 64));
		int chunk = keys.header().chunkSize();
		long chunks = Math.max(1, (free + chunk + CipherSuite.TAG_LENGTH - 1) / (chunk + CipherSuite.TAG_LENGTH));
		return Math.max(0, free - chunks * CipherSuite.TAG_LENGTH);
	}

	/**
	 * Enlarges the container to {@code newSize} bytes. The new space is filled
	 * with random data first. A crash during growing leaves a valid container,
	 * possibly with only part of the new space.
	 */
	public void grow(long newSize, ProgressListener progress) throws IOException
	{
		checkOpen();
		if (newSize <= size)
			throw new IllegalArgumentException("new size must be larger than the current size of " + size + " bytes");
		RandomFill.fill(channel, List.of(new Extent(size, newSize - size)), progress);
		channel.force(true);
		size = newSize;
	}

	/**
	 * Overwrites all free space with random data. Useful after a crash, which
	 * can interrupt the wiping that follows a commit, or after working with
	 * wipe on delete switched off. Commits first.
	 */
	public void wipeFreeSpace(ProgressListener progress) throws IOException
	{
		commit();
		RandomFill.fill(channel, allocated.gaps(DATA_OFFSET, size), progress);
		channel.force(true);
	}

	/** Whether space freed by deleting or replacing files is overwritten after each commit. Default: on. */
	public boolean isWipeOnDelete()
	{
		return wipeOnDelete;
	}

	public void setWipeOnDelete(boolean wipeOnDelete)
	{
		this.wipeOnDelete = wipeOnDelete;
	}

	private long gapTotal()
	{
		return size - DATA_OFFSET - allocated.total();
	}

	/** Space kept for the next index, with {@code extraIndexBytes} more entries than now. */
	private long reserve(long extraIndexBytes)
	{
		return sealedSize(indexBytes + extraIndexBytes + INDEX_MARGIN);
	}

	/** Encrypted size of a stream with {@code plain} bytes. */
	long sealedSize(long plain)
	{
		int chunk = keys.header().chunkSize();
		long chunks = Math.max(1, (plain + chunk - 1) / chunk);
		return plain + chunks * CipherSuite.TAG_LENGTH;
	}

	/**
	 * Writes a file's encrypted content into free space, claiming gaps as it
	 * goes and never eating into the index reserve.
	 */
	private final class ExtentWriter extends OutputStream
	{
		private final int entryBase;
		private final long sealedHint;
		private final List<Extent> done = new ArrayList<>();
		private long start;
		private long pos;
		private long end;
		private boolean active;

		ExtentWriter(int entryBase, long sealedHint)
		{
			this.entryBase = entryBase;
			this.sealedHint = sealedHint;
		}

		@Override
		public void write(int b) throws IOException
		{
			write(new byte[] { (byte) b }, 0, 1);
		}

		@Override
		public void write(byte[] b, int off, int len) throws IOException
		{
			java.util.Objects.checkFromIndexSize(off, len, b.length);
			while (len > 0)
			{
				if (!active || pos == end)
					claim();
				int n = (int) Math.min(len, end - pos);
				ByteBuffer buf = ByteBuffer.wrap(b, off, n);
				while (buf.hasRemaining())
					pos += channel.write(buf, pos);
				off += n;
				len -= n;
			}
		}

		private void claim() throws ContainerFullException
		{
			if (active)
				done.add(new Extent(start, pos - start));
			active = false;
			if (done.size() >= Index.MAX_EXTENTS_PER_FILE)
				throw new ContainerFullException("free space is too fragmented", freeBytes());

			List<Extent> gaps = allocated.gaps(DATA_OFFSET, size);
			long free = gaps.stream().mapToLong(Extent::length).sum()
					- reserve(entryBase + 16L * (done.size() + 1));
			if (free <= 0 || gaps.isEmpty())
				throw new ContainerFullException("the container is full", Math.max(0, free));

			Extent gap = gaps.get(0);
			if (done.isEmpty() && sealedHint > 0)
			{
				// Known size: prefer a gap that holds the whole file, else the largest one.
				gap = gaps.stream().filter(g -> g.length() >= sealedHint).findFirst()
						.orElseGet(() -> gaps.stream().max((x, y) -> Long.compare(x.length(), y.length())).orElseThrow());
			}
			long length = Math.min(gap.length(), free);
			start = pos = gap.offset();
			end = start + length;
			allocated.add(new Extent(start, length));
			active = true;
		}

		/** Releases the unused rest of the last claim and returns the written extents. */
		List<Extent> finish()
		{
			if (active)
			{
				if (pos > start)
					done.add(new Extent(start, pos - start));
				if (end > pos)
					allocated.remove(new Extent(pos, end - pos));
				active = false;
			}
			return done;
		}

		/** Releases everything after a failure; the partial content was never referenced. */
		void abort()
		{
			List<Extent> written = finish();
			written.forEach(allocated::remove);
			if (wipeOnDelete && !written.isEmpty())
			{
				try
				{
					RandomFill.fill(channel, written, ProgressListener.NONE);
				}
				catch (IOException e)
				{
					// Best effort; the space is free either way and wipeFreeSpace can repeat it.
				}
			}
		}
	}

	/** Encrypts {@code data} into exactly the given extents (their total must equal the sealed size). */
	private void writeFixed(List<Extent> target, byte[] salt, byte[] aad, byte[] data) throws IOException
	{
		OutputStream raw = new OutputStream()
		{
			private int index;
			private long pos = target.get(0).offset();

			@Override
			public void write(int b) throws IOException
			{
				write(new byte[] { (byte) b }, 0, 1);
			}

			@Override
			public void write(byte[] b, int off, int len) throws IOException
			{
				while (len > 0)
				{
					if (pos == target.get(index).end())
						pos = target.get(++index).offset();
					int n = (int) Math.min(len, target.get(index).end() - pos);
					ByteBuffer buf = ByteBuffer.wrap(b, off, n);
					while (buf.hasRemaining())
						pos += channel.write(buf, pos);
					off += n;
					len -= n;
				}
			}
		};
		byte[] key = keys.streamKey(salt);
		try
		{
			ChunkedAeadOutputStream enc = new ChunkedAeadOutputStream(raw, keys.header().cipherSuite(), key, aad,
					keys.header().chunkSize());
			enc.write(data);
			enc.finish();
		}
		finally
		{
			Passwords.wipe(key);
		}
	}

	// ================================================================== key slots

	/** The current header, e.g. to show the key slots. */
	public ContainerHeader header()
	{
		checkOpen();
		return keys.header();
	}

	public void addPasswordSlot(char[] password, Argon2Params params) throws IOException
	{
		checkOpen();
		keys.addPasswordSlot(password, params);
		writeHeaderCopies();
	}

	public void addPublicKeySlot(HybridPublicKey recipient) throws IOException
	{
		checkOpen();
		keys.addPublicKeySlot(recipient);
		writeHeaderCopies();
	}

	/** See {@link UnlockedHeader#removeKeySlot(int)} for what removing a slot does and does not achieve. */
	public void removeKeySlot(int index) throws IOException
	{
		checkOpen();
		keys.removeKeySlot(index);
		writeHeaderCopies();
	}

	/** Writes copy B, then copy A, each forced to disk, so one valid copy always exists. */
	private void writeHeaderCopies() throws IOException
	{
		byte[] area = keys.header().encode();
		ChannelIO.writeFully(channel, area, HEADER_B_OFFSET);
		channel.force(true);
		ChannelIO.writeFully(channel, area, 0);
		channel.force(true);
	}

	/** After a crash during a header change the copies differ; make both equal to the one that opened. */
	private void repairHeaderCopies(byte[] areaA, byte[] areaB) throws IOException
	{
		byte[] good = keys.header().encode();
		if (!Arrays.equals(good, areaA) || !Arrays.equals(good, areaB))
			writeHeaderCopies();
	}

	// ================================================================== internals

	private void loadIndex() throws IOException
	{
		Superblock a = Superblock.decode(ChannelIO.readFully(channel, SUPERBLOCK_OFFSET, Superblock.SIZE), keys);
		Superblock b = Superblock.decode(ChannelIO.readFully(channel, SUPERBLOCK_OFFSET + Superblock.SIZE, Superblock.SIZE), keys);
		Superblock sb = a == null ? b : b == null ? a : a.generation() >= b.generation() ? a : b;
		if (sb == null)
			throw new IntegrityException("no valid superblock");

		ExtentSet used = new ExtentSet();
		claimChecked(used, sb.indexExtents());
		byte[] data;
		try (InputStream in = openStream(sb.indexSalt(), sb.indexExtents(), INDEX_AAD))
		{
			data = in.readAllBytes();
		}
		try
		{
			items = Index.decode(data);
		}
		catch (FormatException e)
		{
			throw new IntegrityException("index is inconsistent: " + e.getMessage());
		}
		indexBytes = 4;
		for (Index.Item it : items.values())
		{
			claimChecked(used, it.extents());
			indexBytes += it.encodedSize();
		}
		allocated = used;
		current = sb;
	}

	/** Adds extents to {@code used}, rejecting any outside the data area or overlapping another. */
	private void claimChecked(ExtentSet used, List<Extent> extents) throws IntegrityException
	{
		for (Extent e : extents)
		{
			if (e.offset() < DATA_OFFSET || e.end() > size)
				throw new IntegrityException("container file is truncated");
			if (used.overlaps(e))
				throw new IntegrityException("index is inconsistent: overlapping contents");
			used.add(e);
		}
	}

	private InputStream openStream(byte[] salt, List<Extent> extents, byte[] aad)
	{
		byte[] key = keys.streamKey(salt);
		try
		{
			return new ChunkedAeadInputStream(ChannelIO.input(channel, extents), keys.header().cipherSuite(), key, aad,
					keys.header().chunkSize());
		}
		finally
		{
			Passwords.wipe(key);
		}
	}

	/** Reports bytes read through {@code in} to {@code progress}. */
	private static InputStream counting(InputStream in, long total, ProgressListener progress)
	{
		progress.progress(0, total);
		return new java.io.FilterInputStream(in)
		{
			private long count;

			@Override
			public int read() throws IOException
			{
				byte[] one = new byte[1];
				return read(one, 0, 1) == -1 ? -1 : one[0] & 0xFF;
			}

			@Override
			public int read(byte[] b, int off, int len) throws IOException
			{
				int n = super.read(b, off, len);
				if (n > 0)
				{
					count += n;
					progress.progress(count, total);
				}
				return n;
			}
		};
	}

	/** Wraps a content stream so that a length differing from the index is an integrity error. */
	private static InputStream verifiedSize(InputStream in, long expected)
	{
		return new java.io.FilterInputStream(in)
		{
			private long count;

			@Override
			public int read() throws IOException
			{
				byte[] one = new byte[1];
				return read(one, 0, 1) == -1 ? -1 : one[0] & 0xFF;
			}

			@Override
			public int read(byte[] b, int off, int len) throws IOException
			{
				int n = super.read(b, off, len);
				if (n > 0)
					count += n;
				if (count > expected || (n == -1 && count != expected))
					throw new IntegrityException("file size does not match the index");
				return n;
			}
		};
	}

	/**
	 * For tests: raw bytes of the container file, read through this
	 * container's own channel. On Windows the file lock is mandatory, so a
	 * second channel cannot read the file while it is open.
	 */
	byte[] rawBytes(long offset, int length) throws IOException
	{
		return ChannelIO.readFully(channel, offset, length);
	}

	/** For tests: where a file's encrypted content lies. */
	List<Extent> extentsOf(String path)
	{
		return items.get(VaultPaths.normalize(path)).extents();
	}

	private static byte[] randomBytes(int n)
	{
		byte[] b = new byte[n];
		RANDOM.nextBytes(b);
		return b;
	}

	private void checkOpen()
	{
		if (closed)
			throw new IllegalStateException("container is closed");
	}

	public Path file()
	{
		return file;
	}

	/** Commits pending changes, wipes the keys and releases the file. */
	@Override
	public void close() throws IOException
	{
		if (closed)
			return;
		try
		{
			commit();
		}
		finally
		{
			closed = true;
			keys.close();
			try
			{
				if (lock.isValid())
					lock.release();
			}
			finally
			{
				channel.close();
			}
		}
	}
}
