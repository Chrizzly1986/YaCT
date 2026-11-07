/*******************************************************************************
 * YaCT | (c) 2015-2026 Christian Hoppe | http://opensource.org/licenses/MIT
 ******************************************************************************/
package yact.core.container;

import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.util.List;
import java.util.Objects;

/** Streams over a region of a {@link FileChannel}, using positional reads and writes. */
final class ChannelIO
{
	private ChannelIO()
	{
	}

	static void writeFully(FileChannel ch, byte[] data, long position) throws IOException
	{
		ByteBuffer buf = ByteBuffer.wrap(data);
		while (buf.hasRemaining())
			position += ch.write(buf, position);
	}

	static byte[] readFully(FileChannel ch, long position, int length) throws IOException
	{
		ByteBuffer buf = ByteBuffer.allocate(length);
		while (buf.hasRemaining())
		{
			int n = ch.read(buf, position + buf.position());
			if (n < 0)
				throw new java.io.EOFException("unexpected end of container file");
		}
		return buf.array();
	}

	/** Reads the concatenation of {@code extents}. */
	static InputStream input(FileChannel ch, List<Extent> extents)
	{
		return new InputStream()
		{
			private int index;
			private long pos = extents.isEmpty() ? 0 : extents.get(0).offset();

			@Override
			public int read() throws IOException
			{
				byte[] one = new byte[1];
				return read(one, 0, 1) == -1 ? -1 : one[0] & 0xFF;
			}

			@Override
			public int read(byte[] b, int off, int len) throws IOException
			{
				Objects.checkFromIndexSize(off, len, b.length);
				if (len == 0)
					return 0;
				while (index < extents.size() && pos >= extents.get(index).end())
				{
					index++;
					if (index < extents.size())
						pos = extents.get(index).offset();
				}
				if (index >= extents.size())
					return -1;
				long remaining = extents.get(index).end() - pos;
				int n = ch.read(ByteBuffer.wrap(b, off, (int) Math.min(len, remaining)), pos);
				if (n > 0)
					pos += n;
				return n;
			}
		};
	}
}
