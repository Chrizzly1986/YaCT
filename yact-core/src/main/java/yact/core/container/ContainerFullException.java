/*******************************************************************************
 * YaCT | (c) 2015-2026 Christian Hoppe | http://opensource.org/licenses/MIT
 ******************************************************************************/
package yact.core.container;

import java.io.IOException;

/** Not enough free space in the container. The container is unchanged and can be enlarged. */
public class ContainerFullException extends IOException
{
	private static final long serialVersionUID = 1L;

	private final long available;

	public ContainerFullException(String message, long available)
	{
		super(message);
		this.available = available;
	}

	/** Free bytes at the time of the failure. */
	public long available()
	{
		return available;
	}
}
