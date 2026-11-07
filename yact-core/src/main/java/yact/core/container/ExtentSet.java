/*******************************************************************************
 * YaCT | (c) 2015-2026 Christian Hoppe | http://opensource.org/licenses/MIT
 ******************************************************************************/
package yact.core.container;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/** A set of non-overlapping byte ranges; adjacent ranges are merged. Not thread-safe. */
final class ExtentSet
{
	/** start -> end (exclusive) */
	private final TreeMap<Long, Long> ranges = new TreeMap<>();

	static ExtentSet of(Collection<Extent> extents)
	{
		ExtentSet s = new ExtentSet();
		for (Extent e : extents)
			s.add(e);
		return s;
	}

	ExtentSet copy()
	{
		ExtentSet s = new ExtentSet();
		s.ranges.putAll(ranges);
		return s;
	}

	void add(Extent e)
	{
		long start = e.offset();
		long end = e.end();
		Map.Entry<Long, Long> before = ranges.floorEntry(start);
		if (before != null && before.getValue() >= start)
		{
			start = before.getKey();
			end = Math.max(end, before.getValue());
		}
		for (Map.Entry<Long, Long> next = ranges.ceilingEntry(start); next != null && next.getKey() <= end;
				next = ranges.ceilingEntry(start))
		{
			end = Math.max(end, next.getValue());
			ranges.remove(next.getKey());
		}
		ranges.put(start, end);
	}

	void remove(Extent e)
	{
		long start = e.offset();
		long end = e.end();
		Map.Entry<Long, Long> before = ranges.lowerEntry(start);
		if (before != null && before.getValue() > start)
		{
			ranges.put(before.getKey(), start);
			if (before.getValue() > end)
				ranges.put(end, before.getValue());
		}
		for (Map.Entry<Long, Long> next = ranges.ceilingEntry(start); next != null && next.getKey() < end;
				next = ranges.ceilingEntry(start))
		{
			ranges.remove(next.getKey());
			if (next.getValue() > end)
				ranges.put(end, next.getValue());
		}
	}

	/** True if any byte of {@code e} is in this set. */
	boolean overlaps(Extent e)
	{
		Map.Entry<Long, Long> before = ranges.floorEntry(e.offset());
		if (before != null && before.getValue() > e.offset())
			return true;
		Long next = ranges.higherKey(e.offset());
		return next != null && next < e.end();
	}

	/** The ranges within {@code [from, to)} that are not in this set, in ascending order. */
	List<Extent> gaps(long from, long to)
	{
		List<Extent> out = new ArrayList<>();
		long pos = from;
		for (Map.Entry<Long, Long> r : ranges.entrySet())
		{
			if (r.getValue() <= pos)
				continue;
			if (r.getKey() >= to)
				break;
			if (r.getKey() > pos)
				out.add(new Extent(pos, r.getKey() - pos));
			pos = Math.max(pos, r.getValue());
		}
		if (pos < to)
			out.add(new Extent(pos, to - pos));
		return out;
	}

	/** This set without the ranges of {@code other}. */
	ExtentSet minus(ExtentSet other)
	{
		ExtentSet s = copy();
		for (Map.Entry<Long, Long> r : other.ranges.entrySet())
			s.remove(new Extent(r.getKey(), r.getValue() - r.getKey()));
		return s;
	}

	List<Extent> extents()
	{
		List<Extent> out = new ArrayList<>(ranges.size());
		for (Map.Entry<Long, Long> r : ranges.entrySet())
			out.add(new Extent(r.getKey(), r.getValue() - r.getKey()));
		return out;
	}

	long total()
	{
		long t = 0;
		for (Map.Entry<Long, Long> r : ranges.entrySet())
			t += r.getValue() - r.getKey();
		return t;
	}
}
