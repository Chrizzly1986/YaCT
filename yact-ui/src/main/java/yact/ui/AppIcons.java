/*******************************************************************************
 * YaCT | (c) 2015-2026 Christian Hoppe | http://opensource.org/licenses/MIT
 ******************************************************************************/
package yact.ui;

import java.util.ArrayList;
import java.util.List;

import javafx.collections.ListChangeListener;
import javafx.scene.image.Image;
import javafx.stage.Stage;
import javafx.stage.Window;

/**
 * The YaCT logo in all sizes. 16 to 32 px use a simplified drawing that stays
 * legible; the sources are in {@code docs/logo}.
 */
final class AppIcons
{
	static final int[] SIZES = { 16, 24, 32, 48, 64, 128, 256, 512 };
	private static List<Image> all;

	private AppIcons()
	{
	}

	static Image image(int size)
	{
		return new Image(AppIcons.class.getResource("icons/yact-" + size + ".png").toExternalForm());
	}

	/** All sizes; the window system picks the best one for title bar, task bar and switcher. */
	static synchronized List<Image> all()
	{
		if (all == null)
		{
			all = new ArrayList<>();
			for (int s : SIZES)
				all.add(image(s));
		}
		return all;
	}

	/** Gives every window opened from now on the logo, including dialogs and progress windows. */
	static void install()
	{
		Window.getWindows().addListener((ListChangeListener<Window>) change -> {
			while (change.next())
				for (Window w : change.getAddedSubList())
					if (w instanceof Stage s && s.getIcons().isEmpty())
						s.getIcons().setAll(all());
		});
	}
}
