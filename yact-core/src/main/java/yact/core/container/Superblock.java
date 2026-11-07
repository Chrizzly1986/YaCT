/*******************************************************************************
 * YaCT | (c) 2015-2026 Christian Hoppe | http://opensource.org/licenses/MIT
 ******************************************************************************/
package yact.core.container;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

import javax.crypto.AEADBadTagException;

import yact.core.codec.ByteReader;
import yact.core.codec.ByteWriter;
import yact.core.codec.FormatException;
import yact.core.crypto.CipherSuite;
import yact.core.crypto.Passwords;
import yact.core.format.UnlockedHeader;

/**
 * Points to the current index. There are two superblock slots, written
 * alternately; the valid one with the higher generation is current. A crash
 * while writing one slot therefore always leaves the previous state intact.
 *
 * <pre>
 * 16    salt
 * 4050  AEAD(plain) + 16-byte tag, plain =
 *         u64  generation
 *         16   index stream salt
 *         u16  number of index extents (1..250)
 *         250 x (u64 offset, u64 length), unused entries zero
 * 30    zero
 * </pre>
 *
 * <p>Key = HKDF(master key, "YaCT v1 superblock key", salt); the salt is fresh
 * for every write, so the all-zero nonce is never reused under one key.
 */
record Superblock(long generation, byte[] indexSalt, List<Extent> indexExtents)
{
	static final int SIZE = 4096;
	static final int SALT_LENGTH = 16;
	static final int MAX_INDEX_EXTENTS = 250;
	private static final int PLAIN_LENGTH = 8 + SALT_LENGTH + 2 + MAX_INDEX_EXTENTS * 16;
	private static final byte[] AAD = "YaCT v1 superblock".getBytes(StandardCharsets.US_ASCII);
	private static final byte[] ZERO_NONCE = new byte[CipherSuite.NONCE_LENGTH];

	Superblock
	{
		indexExtents = List.copyOf(indexExtents);
		if (indexExtents.size() > MAX_INDEX_EXTENTS)
			throw new IllegalArgumentException("index has too many extents");
	}

	/** Slot this generation is written to. */
	int slot()
	{
		return (int) (generation & 1);
	}

	byte[] encode(UnlockedHeader keys, SecureRandom random)
	{
		byte[] salt = new byte[SALT_LENGTH];
		random.nextBytes(salt);
		ByteWriter w = new ByteWriter().u63(generation).bytes(indexSalt).u16(indexExtents.size());
		for (Extent e : indexExtents)
			w.u63(e.offset()).u63(e.length());
		byte[] plain = java.util.Arrays.copyOf(w.toByteArray(), PLAIN_LENGTH);

		byte[] key = keys.superblockKey(salt);
		try
		{
			byte[] sealed = keys.header().cipherSuite().seal(key, ZERO_NONCE, AAD, plain);
			byte[] out = new byte[SIZE];
			System.arraycopy(salt, 0, out, 0, SALT_LENGTH);
			System.arraycopy(sealed, 0, out, SALT_LENGTH, sealed.length);
			return out;
		}
		finally
		{
			Passwords.wipe(key);
		}
	}

	/** @return the superblock, or {@code null} if the slot is empty, torn or not authentic */
	static Superblock decode(byte[] slot, UnlockedHeader keys)
	{
		byte[] salt = java.util.Arrays.copyOf(slot, SALT_LENGTH);
		byte[] key = keys.superblockKey(salt);
		try
		{
			byte[] plain = keys.header().cipherSuite().open(key, ZERO_NONCE, AAD, slot, SALT_LENGTH,
					PLAIN_LENGTH + CipherSuite.TAG_LENGTH);
			ByteReader r = new ByteReader(plain);
			long generation = r.u63();
			byte[] indexSalt = r.bytes(SALT_LENGTH);
			int count = r.u16();
			if (count < 1 || count > MAX_INDEX_EXTENTS)
				return null;
			List<Extent> extents = new ArrayList<>(count);
			for (int i = 0; i < count; i++)
				extents.add(new Extent(r.u63(), r.u63()));
			return new Superblock(generation, indexSalt, extents);
		}
		catch (AEADBadTagException | FormatException | IllegalArgumentException e)
		{
			return null;
		}
		finally
		{
			Passwords.wipe(key);
		}
	}
}
