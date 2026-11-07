/*******************************************************************************
 * YaCT | (c) 2015-2026 Christian Hoppe | http://opensource.org/licenses/MIT
 ******************************************************************************/
package yact.core.container;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.FileTime;
import java.security.SecureRandom;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import yact.core.crypto.Argon2Params;
import yact.core.crypto.CipherSuite;
import yact.core.format.ContainerFormatException;
import yact.core.format.ContainerHeader;
import yact.core.format.IntegrityException;
import yact.core.format.InvalidCredentialsException;
import yact.core.pq.HybridKem;
import yact.core.pq.HybridKeyPair;

class ContainerTest
{
	private static final Argon2Params FAST = new Argon2Params(64, 1, 1);
	private static final char[] PASSWORD = "container password".toCharArray();
	private static final SecureRandom RANDOM = new SecureRandom();
	private static final Instant TIME = Instant.parse("2026-01-02T03:04:05.678Z");

	@TempDir
	Path tmp;
	Path file;

	@BeforeEach
	void setUp()
	{
		file = tmp.resolve("vault.yact");
	}

	private static final long SIZE = 4L << 20;

	private Container create() throws IOException
	{
		return Container.create(file, CipherSuite.AES_256_GCM, PASSWORD, FAST, SIZE, ProgressListener.NONE);
	}

	private Container open() throws Exception
	{
		return Container.open(file, PASSWORD);
	}

	private static void add(Container c, String path, byte[] content) throws IOException
	{
		c.add(path, new ByteArrayInputStream(content), TIME, false);
	}

	private static byte[] read(Container c, String path) throws IOException
	{
		try (InputStream in = c.read(path))
		{
			return in.readAllBytes();
		}
	}

	// ================================================================== basics

	@Test
	void newContainerIsEmptyAndReopens() throws Exception
	{
		create().close();
		assertEquals(SIZE, Files.size(file));
		try (Container c = open())
		{
			assertTrue(c.list().isEmpty());
			assertEquals(SIZE, c.size());
			long free = c.freeBytes();
			assertTrue(free > SIZE - Container.DATA_OFFSET - 100_000 && free < SIZE - Container.DATA_OFFSET, "free " + free);
		}
	}

	@Test
	void createRefusesExistingFile() throws IOException
	{
		Files.writeString(file, "precious data");
		assertThrows(FileAlreadyExistsException.class, this::create);
		assertEquals("precious data", Files.readString(file));
	}

	@Test
	void filesSurviveReopening() throws Exception
	{
		byte[] small = random(10);
		byte[] large = random(3 * (1 << ContainerHeader.DEFAULT_CHUNK_EXPONENT) + 123);
		try (Container c = create())
		{
			add(c, "notes.txt", small);
			add(c, "photos/2026/big.bin", large);
			add(c, "empty", new byte[0]);
		}
		try (Container c = open())
		{
			assertEquals(List.of("empty", "notes.txt", "photos/2026/big.bin"), c.list().stream().map(ContainerEntry::path).toList());
			assertArrayEquals(small, read(c, "notes.txt"));
			assertArrayEquals(large, read(c, "photos/2026/big.bin"));
			assertArrayEquals(new byte[0], read(c, "empty"));

			ContainerEntry e = c.entry("photos/2026/big.bin").orElseThrow();
			assertEquals(large.length, e.size());
			assertEquals(TIME, e.modified());
			assertEquals("big.bin", e.name());
			assertEquals(1, c.list("photos").size());
			assertEquals(0, c.list("photo").size(), "prefix must match whole segments");
		}
	}

	@Test
	void privateKeyContainer() throws Exception
	{
		HybridKeyPair key = HybridKeyPair.generate(HybridKem.DEFAULT, RANDOM);
		try (Container c = Container.create(file, CipherSuite.CHACHA20_POLY1305, key.publicKey(), SIZE, ProgressListener.NONE))
		{
			add(c, "secret", "pq".getBytes());
		}
		try (Container c = Container.open(file, key))
		{
			assertArrayEquals("pq".getBytes(), read(c, "secret"));
		}
		assertThrows(InvalidCredentialsException.class, this::open);
	}

	@Test
	void wrongPasswordAndForeignFiles() throws Exception
	{
		create().close();
		assertThrows(InvalidCredentialsException.class, () -> Container.open(file, "wrong".toCharArray()));

		Path other = tmp.resolve("other.bin");
		Files.write(other, random((int) Container.DATA_OFFSET + 100));
		assertThrows(ContainerFormatException.class, () -> Container.open(other, PASSWORD));
		Files.write(other, random(10));
		assertThrows(ContainerFormatException.class, () -> Container.open(other, PASSWORD));
	}

	@Test
	void containerCanOnlyBeOpenedOnce() throws Exception
	{
		Container first = create();
		try
		{
			IOException e = assertThrows(IOException.class, this::open);
			assertEquals("container is already open", e.getMessage());
		}
		finally
		{
			first.close();
		}
		open().close();
	}

	// ================================================================== paths

	@Test
	void pathsAreNormalized() throws Exception
	{
		try (Container c = create())
		{
			add(c, "\\docs\\a.txt", random(1));
			add(c, "/docs/b.txt/", random(1));
			add(c, "Grüße.txt", random(1));
			assertEquals(List.of("Grüße.txt", "docs/a.txt", "docs/b.txt"), c.list().stream().map(ContainerEntry::path).toList());
			assertTrue(c.entry("docs\\a.txt").isPresent());
		}
	}

	@Test
	void unsafePathsAreRejected() throws Exception
	{
		try (Container c = create())
		{
			for (String bad : List.of("", "/", "../x", "a/../b", "a//b", "./a", "a/.", "a\u0000b", "a\nb"))
				assertThrows(IllegalArgumentException.class, () -> add(c, bad, random(1)), bad);
			assertTrue(c.list().isEmpty());
		}
	}

	@Test
	void fileAndDirectoryCannotShareAName() throws Exception
	{
		try (Container c = create())
		{
			add(c, "a/b", random(1));
			assertThrows(IllegalArgumentException.class, () -> add(c, "a", random(1)));
			assertThrows(IllegalArgumentException.class, () -> add(c, "a/b/c", random(1)));
			add(c, "x", random(1));
			assertThrows(IllegalArgumentException.class, () -> c.rename("x", "a/b/c"));
			assertTrue(c.entry("x").isPresent(), "failed rename keeps the file");
		}
	}

	// ================================================================== changes

	@Test
	void overwriteDeleteAndRename() throws Exception
	{
		try (Container c = create())
		{
			add(c, "a", "one".getBytes());
			assertThrows(FileAlreadyExistsException.class, () -> add(c, "a", "two".getBytes()));
			c.add("a", new ByteArrayInputStream("two".getBytes()), TIME, true);
			assertArrayEquals("two".getBytes(), read(c, "a"));

			c.rename("a", "dir/b");
			assertFalse(c.entry("a").isPresent());
			assertArrayEquals("two".getBytes(), read(c, "dir/b"));

			add(c, "dir/c", random(5));
			add(c, "dirt", random(5));
			assertEquals(2, c.deleteDirectory("dir"));
			assertEquals(List.of("dirt"), c.list().stream().map(ContainerEntry::path).toList());

			c.delete("dirt");
			assertThrows(NoSuchFileException.class, () -> c.delete("dirt"));
			assertThrows(NoSuchFileException.class, () -> c.read("dirt"));
		}
		try (Container c = open())
		{
			assertTrue(c.list().isEmpty());
		}
	}

	// ================================================================== fixed size, free space, wiping

	@Test
	void sizeIsCheckedAndProgressReported() throws Exception
	{
		assertThrows(IllegalArgumentException.class,
				() -> Container.create(file, CipherSuite.AES_256_GCM, PASSWORD, FAST, Container.MIN_SIZE - 1, ProgressListener.NONE));
		long[] last = new long[2];
		Container.create(file, CipherSuite.AES_256_GCM, PASSWORD, FAST, SIZE, (done, total) -> {
			last[0] = done;
			last[1] = total;
		}).close();
		assertEquals(SIZE - Container.DATA_OFFSET, last[1]);
		assertEquals(last[1], last[0]);
	}

	/** Free space must look like ciphertext: no zero runs that show how much is stored. */
	@Test
	void freeSpaceIsRandom() throws Exception
	{
		create().close();
		byte[] data = Files.readAllBytes(file);
		int zeros = 0;
		for (int i = (int) Container.DATA_OFFSET + 4096; i < data.length; i++)
			if (data[i] == 0)
				zeros++;
		double expected = (data.length - Container.DATA_OFFSET) / 256.0;
		assertTrue(zeros > expected * 0.8 && zeros < expected * 1.2, zeros + " zero bytes, expected about " + expected);
	}

	@Test
	void fullContainerRejectsContentAndStaysUnchanged() throws Exception
	{
		try (Container c = create())
		{
			long free = c.freeBytes();
			assertThrows(ContainerFullException.class, () -> add(c, "too-big", random((int) SIZE)));
			assertTrue(c.list().isEmpty());
			assertEquals(free, c.freeBytes(), "space of the aborted file is released");

			Path big = tmp.resolve("big.bin");
			Files.write(big, random((int) SIZE));
			assertThrows(ContainerFullException.class, () -> c.importPath(big, "", false), "checked up front");
			add(c, "small", random(1000));
		}
	}

	@Test
	void fullContainerStillAllowsDeleting() throws Exception
	{
		try (Container c = create())
		{
			int n = 0;
			try
			{
				while (true)
					add(c, "f" + n++, random(200_000));
			}
			catch (ContainerFullException expected)
			{
				// full
			}
			// Use up the rest exactly: the index reserve must still let the commit through.
			long rest = c.freeBytesForContent();
			assertTrue(rest < 200_000);
			add(c, "rest", random((int) rest));
			c.commit();
			assertThrows(ContainerFullException.class, () -> add(c, "one more", random(20_000)));

			c.delete("f0");
			c.commit();
			add(c, "again", random(150_000));
		}
		try (Container c = open())
		{
			assertTrue(c.entry("again").isPresent());
		}
	}

	@Test
	void growMakesRoomAndPersists() throws Exception
	{
		byte[] content = random(6 << 20);
		try (Container c = create())
		{
			assertThrows(ContainerFullException.class, () -> add(c, "big", content));
			assertThrows(IllegalArgumentException.class, () -> c.grow(SIZE, ProgressListener.NONE));
			c.grow(SIZE * 2, ProgressListener.NONE);
			assertEquals(SIZE * 2, Files.size(file));
			add(c, "big", content);
		}
		try (Container c = open())
		{
			assertEquals(SIZE * 2, c.size());
			assertArrayEquals(content, read(c, "big"));
		}
	}

	@Test
	void freedSpaceIsReused() throws Exception
	{
		byte[] second = random(2_500_000);
		try (Container c = create())
		{
			add(c, "first", random(2_500_000)); // two of these do not fit at once
			c.commit();
			c.delete("first");
			assertThrows(ContainerFullException.class, () -> add(c, "x", random(2_500_000)), "freed only after commit");
			c.commit();
			add(c, "second", second);
		}
		try (Container c = open())
		{
			assertArrayEquals(second, read(c, "second"));
			assertEquals(SIZE, Files.size(file));
		}
	}

	@Test
	void filesAreSpreadOverFreeGaps() throws Exception
	{
		byte[] big = random(1_200_000);
		try (Container c = create())
		{
			for (int i = 0; i < 10; i++)
				add(c, "f" + i, random(300_000));
			c.commit();
			for (int i = 0; i < 10; i += 2)
				c.delete("f" + i);
			c.commit();
			c.importPath(write("big", big), "", false);
			assertTrue(c.extentsOf("big").size() > 1, "stored in several gaps");
		}
		try (Container c = open())
		{
			assertArrayEquals(big, read(c, "big"));
			for (int i = 1; i < 10; i += 2)
				assertEquals(300_000, read(c, "f" + i).length);
		}
	}

	@Test
	void deletedContentIsOverwritten() throws Exception
	{
		try (Container c = create())
		{
			add(c, "secret", random(300_000));
			c.commit();
			List<Extent> where = c.extentsOf("secret");
			byte[] before = rawBytes(where);
			c.delete("secret");
			c.commit();
			assertMostlyDifferent(before, rawBytes(where));
		}
	}

	@Test
	void replacedContentIsOverwritten() throws Exception
	{
		try (Container c = create())
		{
			add(c, "doc", random(300_000));
			c.commit();
			List<Extent> where = c.extentsOf("doc");
			byte[] before = rawBytes(where);
			c.add("doc", new ByteArrayInputStream(random(10)), TIME, true);
			c.commit();
			assertMostlyDifferent(before, rawBytes(where));
		}
	}

	@Test
	void withoutWipingDeletedContentStays() throws Exception
	{
		try (Container c = create())
		{
			assertTrue(c.isWipeOnDelete(), "on by default");
			c.setWipeOnDelete(false);
			add(c, "secret", random(300_000));
			c.commit();
			List<Extent> where = c.extentsOf("secret");
			byte[] before = rawBytes(where);
			c.delete("secret");
			c.commit();
			assertArrayEquals(before, rawBytes(where));

			c.wipeFreeSpace(ProgressListener.NONE);
			assertMostlyDifferent(before, rawBytes(where));
		}
	}

	@Test
	void failedAddReleasesItsSpace() throws Exception
	{
		try (Container c = create())
		{
			long free = c.freeBytes();
			InputStream failing = new InputStream()
			{
				private int n;

				@Override
				public int read()
				{
					if (n++ > 500_000)
						throw new java.io.UncheckedIOException(new IOException("disk read error"));
					return 7;
				}
			};
			assertThrows(java.io.UncheckedIOException.class, () -> c.add("broken", failing, TIME, false));
			assertFalse(c.entry("broken").isPresent());
			assertEquals(free, c.freeBytes());
		}
	}

	// ================================================================== import / export

	@Test
	void importAndExportDirectoryTrees() throws Exception
	{
		Path src = Files.createDirectories(tmp.resolve("src/project"));
		Files.write(src.resolve("readme.md"), "hello".getBytes());
		Files.createDirectories(src.resolve("lib/deep"));
		byte[] bin = random(100_000);
		Files.write(src.resolve("lib/deep/data.bin"), bin);
		Files.setLastModifiedTime(src.resolve("readme.md"), FileTime.from(TIME));
		Files.createSymbolicLink(src.resolve("link"), src.resolve("readme.md"));

		try (Container c = create())
		{
			c.importPath(src, "backup", false);
			assertEquals(List.of("backup/project/lib/deep/data.bin", "backup/project/readme.md"),
					c.list().stream().map(ContainerEntry::path).toList(), "symlink skipped");

			Path out = tmp.resolve("out");
			c.extractAll("backup", out, false);
			assertEquals("hello", Files.readString(out.resolve("project/readme.md")));
			assertArrayEquals(bin, Files.readAllBytes(out.resolve("project/lib/deep/data.bin")));
			assertEquals(TIME.truncatedTo(ChronoUnit.MILLIS),
					Files.getLastModifiedTime(out.resolve("project/readme.md")).toInstant().truncatedTo(ChronoUnit.MILLIS));

			assertThrows(FileAlreadyExistsException.class, () -> c.extractAll("backup", out, false));
			c.extractAll("backup", out, true);
		}
	}

	// ================================================================== tampering and crashes

	@Test
	void modifiedContentIsDetectedAndNoPartialFileIsLeft() throws Exception
	{
		try (Container c = create())
		{
			add(c, "victim", random(200_000));
		}
		flipByte(Container.DATA_OFFSET + 70_000);
		try (Container c = open())
		{
			assertThrows(IntegrityException.class, () -> read(c, "victim"));
			Path target = tmp.resolve("victim.out");
			assertThrows(IntegrityException.class, () -> c.extract("victim", target, false));
			assertFalse(Files.exists(target));
			try (var files = Files.list(tmp))
			{
				assertEquals(1, files.count(), "temporary file removed");
			}
		}
	}

	@Test
	void truncatedContainerIsDetected() throws Exception
	{
		try (Container c = create())
		{
			add(c, "f", random(1000));
		}
		try (FileChannel ch = FileChannel.open(file, StandardOpenOption.WRITE))
		{
			ch.truncate(Container.DATA_OFFSET + 500); // cuts into the file content
		}
		assertThrows(IntegrityException.class, this::open);
	}

	@Test
	void uncommittedChangesAreNotVisibleAfterACrash() throws Exception
	{
		Path snapshot = tmp.resolve("snapshot.yact");
		try (Container c = create())
		{
			add(c, "committed", random(10));
			c.commit();
			add(c, "pending", random(10));
			assertTrue(c.hasUncommittedChanges());
			Files.copy(file, snapshot); // the state on disk if the program died now
		}
		try (Container c = Container.open(snapshot, PASSWORD))
		{
			assertEquals(List.of("committed"), c.list().stream().map(ContainerEntry::path).toList());
		}
	}

	@Test
	void tornSuperblockFallsBackToThePreviousState() throws Exception
	{
		// The fallback covers a crash while the new superblock is being written. At that moment the old
		// index is still intact: freed space is only wiped or reused after the superblock is on disk.
		// With wiping off and enough free space, the old index stays untouched, which recreates that moment.
		try (Container c = create())
		{
			c.setWipeOnDelete(false);
			add(c, "first", random(10));
			c.commit();
			add(c, "second", random(10));
		}
		// Generations: 1 = empty (create, slot 1), 2 = "first" (slot 0), 3 = both files (close, slot 1).
		byte[] original = Files.readAllBytes(file);
		flipByte(Container.SUPERBLOCK_OFFSET + Superblock.SIZE + 20); // damage generation 3
		try (Container c = open())
		{
			assertEquals(List.of("first"), c.list().stream().map(ContainerEntry::path).toList());
		}
		Files.write(file, original);
		flipByte(Container.SUPERBLOCK_OFFSET + 20); // damage generation 2: generation 3 is still current
		try (Container c = open())
		{
			assertEquals(2, c.list().size());
		}
		try (FileChannel ch = FileChannel.open(file, StandardOpenOption.WRITE))
		{
			ch.write(ByteBuffer.allocate(2 * Superblock.SIZE), Container.SUPERBLOCK_OFFSET);
		}
		assertThrows(IntegrityException.class, this::open);
	}

	@Test
	void damagedHeaderCopyIsRepaired() throws Exception
	{
		create().close();
		byte[] good = Files.readAllBytes(file);
		for (long offset : new long[] { 0, Container.HEADER_B_OFFSET })
		{
			Files.write(file, good);
			flipByte(offset + 2); // magic
			open().close();
			assertArrayEquals(good, Files.readAllBytes(file), "copy at " + offset + " repaired");
		}
	}

	@Test
	void crashDuringPasswordChangeLeavesAWorkingContainer() throws Exception
	{
		char[] newPassword = "new password".toCharArray();
		byte[] oldHeader;
		try (Container c = create())
		{
			oldHeader = c.header().encode();
			c.addPasswordSlot(newPassword, FAST);
			c.removeKeySlot(0);
		}
		// Simulate a crash after copy B was written but before copy A: A still holds the old header.
		try (FileChannel ch = FileChannel.open(file, StandardOpenOption.WRITE))
		{
			ch.write(ByteBuffer.wrap(oldHeader), 0);
		}
		try (Container c = Container.open(file, newPassword))
		{
			assertEquals(1, c.header().keySlots().size());
		}
		// Opening repaired copy A, so the removed password is gone from both copies.
		assertThrows(InvalidCredentialsException.class, this::open);
	}

	@Test
	void keySlotChangesArePersisted() throws Exception
	{
		HybridKeyPair key = HybridKeyPair.generate(HybridKem.DEFAULT, RANDOM);
		try (Container c = create())
		{
			add(c, "f", "x".getBytes());
			c.addPublicKeySlot(key.publicKey());
		}
		try (Container c = Container.open(file, key))
		{
			assertArrayEquals("x".getBytes(), read(c, "f"));
			c.removeKeySlot(0); // the password slot
		}
		assertThrows(InvalidCredentialsException.class, this::open);
		Container.open(file, key).close();
	}

	@Test
	void closedContainerCannotBeUsed() throws Exception
	{
		Container c = create();
		c.close();
		c.close(); // idempotent
		assertThrows(IllegalStateException.class, c::list);
	}

	// ================================================================== helpers

	private byte[] rawBytes(List<Extent> extents) throws IOException
	{
		java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
		try (FileChannel ch = FileChannel.open(file, StandardOpenOption.READ))
		{
			for (Extent e : extents)
				out.write(ChannelIO.readFully(ch, e.offset(), (int) e.length()));
		}
		return out.toByteArray();
	}

	private static void assertMostlyDifferent(byte[] before, byte[] after)
	{
		assertEquals(before.length, after.length);
		int same = 0;
		for (int i = 0; i < before.length; i++)
			if (before[i] == after[i])
				same++;
		// Random data matches by chance in about 1 of 256 bytes.
		assertTrue(same < before.length / 100, same + " of " + before.length + " bytes unchanged");
	}

	private Path write(String name, byte[] content) throws IOException
	{
		Path p = tmp.resolve(name);
		Files.write(p, content);
		return p;
	}

	private void flipByte(long offset) throws IOException
	{
		try (FileChannel ch = FileChannel.open(file, StandardOpenOption.READ, StandardOpenOption.WRITE))
		{
			ByteBuffer b = ByteBuffer.allocate(1);
			ch.read(b, offset);
			b.put(0, (byte) (b.get(0) ^ 1));
			b.rewind();
			ch.write(b, offset);
		}
	}

	private static byte[] random(int n)
	{
		byte[] b = new byte[n];
		RANDOM.nextBytes(b);
		return b;
	}
}
