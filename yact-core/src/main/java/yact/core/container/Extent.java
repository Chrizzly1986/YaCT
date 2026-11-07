/*******************************************************************************
 * YaCT | (c) 2015-2026 Christian Hoppe | http://opensource.org/licenses/MIT
 ******************************************************************************/
package yact.core.container;

/** A contiguous byte range of the container file: {@code [offset, offset + length)}. */
record Extent(long offset, long length)
{
	Extent
	{
		if (offset < 0 || length <= 0 || offset > Long.MAX_VALUE - length)
			throw new IllegalArgumentException("invalid extent " + offset + "+" + length);
	}

	long end()
	{
		return offset + length;
	}
}
