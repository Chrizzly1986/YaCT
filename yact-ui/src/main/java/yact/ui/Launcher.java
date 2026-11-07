/*******************************************************************************
 * YaCT | (c) 2015-2026 Christian Hoppe | http://opensource.org/licenses/MIT
 ******************************************************************************/
package yact.ui;

/**
 * Entry point for a plain {@code java -cp ...} start. JavaFX refuses to
 * start an {@code Application} subclass directly from the class path, so
 * this class, which is not one, launches it.
 */
public final class Launcher
{
	private Launcher()
	{
	}

	public static void main(String[] args)
	{
		javafx.application.Application.launch(YactApp.class, args);
	}
}
