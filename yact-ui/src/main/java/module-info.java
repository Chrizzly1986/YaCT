/*******************************************************************************
 * YaCT | (c) 2015-2026 Christian Hoppe | http://opensource.org/licenses/MIT
 ******************************************************************************/

/**
 * The YaCT desktop application. Exported only to JavaFX, which has to create
 * the {@code Application} instance; no package is opened to reflection.
 */
module yact.ui
{
	requires yact.core;
	requires javafx.controls;
	requires java.management; // runtime checks against injected agents, see Launcher

	exports yact.ui to javafx.graphics;
}
