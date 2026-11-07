/*******************************************************************************
 * YaCT | (c) 2015-2026 Christian Hoppe | http://opensource.org/licenses/MIT
 ******************************************************************************/
package yact.core.container;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

import yact.core.codec.ByteReader;
import yact.core.codec.ByteWriter;
import yact.core.codec.FormatException;

/**
 * The container's table of contents. Stored as one encrypted stream.
 *
 * <pre>
 * u32  number of entries
 * per entry:
 *   u16  path length, path (UTF-8)
 *   u64  plaintext size
 *   u64  modified, milliseconds since 1970-01-01T00:00Z
 *   16   stream salt of the file content
 *   u32  number of extents
 *   per extent: u64 offset, u64 length
 * </pre>
 *
 * <p>The encrypted content of a file is the concatenation of its extents.
 */
final class Index
{
	static final int MAX_ENTRIES = 10_000_000;
	static final int MAX_EXTENTS_PER_FILE = 1_000_000;

	/** Where a file's encrypted content lives. */
	record Item(ContainerEntry entry, byte[] salt, List<Extent> extents)
	{
		Item
		{
			extents = List.copyOf(extents);
		}

		long sealedLength()
		{
			long n = 0;
			for (Extent e : extents)
				n += e.length();
			return n;
		}

		Item withPath(String path)
		{
			return new Item(new ContainerEntry(path, entry.size(), entry.modified()), salt, extents);
		}

		/** Bytes this entry takes in the encoded index. */
		int encodedSize()
		{
			return 2 + entry.path().getBytes(StandardCharsets.UTF_8).length + 8 + 8 + 16 + 4 + 16 * extents.size();
		}
	}

	private Index()
	{
	}

	static byte[] encode(Map<String, Item> items)
	{
		ByteWriter w = new ByteWriter().u31(items.size());
		for (Item it : items.values())
		{
			byte[] path = it.entry().path().getBytes(StandardCharsets.UTF_8);
			w.u16(path.length).bytes(path)
					.u63(it.entry().size())
					.u63(Math.max(0, it.entry().modified().toEpochMilli()))
					.bytes(it.salt())
					.u31(it.extents().size());
			for (Extent e : it.extents())
				w.u63(e.offset()).u63(e.length());
		}
		return w.toByteArray();
	}

	static TreeMap<String, Item> decode(byte[] data) throws FormatException
	{
		ByteReader r = new ByteReader(data);
		int count = r.u31();
		if (count > MAX_ENTRIES)
			throw new FormatException("too many index entries");
		TreeMap<String, Item> items = new TreeMap<>();
		for (int i = 0; i < count; i++)
		{
			String path = new String(r.bytes(r.u16()), StandardCharsets.UTF_8);
			try
			{
				VaultPaths.check(path);
			}
			catch (IllegalArgumentException e)
			{
				throw new FormatException("invalid path in index: " + e.getMessage());
			}
			long size = r.u63();
			Instant modified = Instant.ofEpochMilli(r.u63());
			byte[] salt = r.bytes(Superblock.SALT_LENGTH);
			int extentCount = r.u31();
			if (extentCount < 1 || extentCount > MAX_EXTENTS_PER_FILE)
				throw new FormatException("invalid number of extents");
			List<Extent> extents = new ArrayList<>(Math.min(extentCount, 1024));
			try
			{
				for (int j = 0; j < extentCount; j++)
					extents.add(new Extent(r.u63(), r.u63()));
			}
			catch (IllegalArgumentException e)
			{
				throw new FormatException(e.getMessage());
			}
			if (items.put(path, new Item(new ContainerEntry(path, size, modified), salt, extents)) != null)
				throw new FormatException("duplicate path in index: " + path);
		}
		r.expectEnd();
		return items;
	}
}
