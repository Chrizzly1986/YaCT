/*******************************************************************************
 * YaCT | (c) 2015-2026 Christian Hoppe | http://opensource.org/licenses/MIT
 ******************************************************************************/

/**
 * YaCT's cryptography and container engine.
 *
 * <p>As a named module its internals are strongly encapsulated: no other code
 * in the process - including the UI toolkit and BouncyCastle - can reach
 * private fields such as the master key by reflection, because no package is
 * opened. The packages are exported only to {@code yact.ui}, so other modules
 * cannot even call the public API.
 */
@SuppressWarnings("module") // yact.ui is compiled later
module yact.core
{
	requires org.bouncycastle.provider; // ML-KEM only, see yact.core.pq.MlKem

	exports yact.core.codec to yact.ui;
	exports yact.core.container to yact.ui;
	exports yact.core.crypto to yact.ui;
	exports yact.core.format to yact.ui;
	exports yact.core.io to yact.ui;
	exports yact.core.pq to yact.ui;
	exports yact.core.stream to yact.ui;
}
