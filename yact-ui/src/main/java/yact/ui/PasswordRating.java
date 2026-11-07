/*******************************************************************************
 * YaCT | (c) 2015-2026 Christian Hoppe | http://opensource.org/licenses/MIT
 ******************************************************************************/
package yact.ui;

/**
 * A rough password rating for the user. It cannot measure real strength:
 * a long password made of common words can be strong, "Passw0rd!" is weak
 * despite its character classes. The rating only catches the obvious cases.
 */
enum PasswordRating
{
	TOO_SHORT, WEAK, OK, STRONG;

	/** For new passwords; unlocking accepts any password. */
	static final int MIN_LENGTH = 12;

	static PasswordRating of(CharSequence pw)
	{
		int length = Character.codePointCount(pw, 0, pw.length());
		if (length < MIN_LENGTH)
			return TOO_SHORT;
		boolean lower = false, upper = false, digit = false, other = false;
		for (int i = 0; i < pw.length(); i++)
		{
			char c = pw.charAt(i);
			if (Character.isLowerCase(c))
				lower = true;
			else if (Character.isUpperCase(c))
				upper = true;
			else if (Character.isDigit(c))
				digit = true;
			else
				other = true;
		}
		int classes = (lower ? 1 : 0) + (upper ? 1 : 0) + (digit ? 1 : 0) + (other ? 1 : 0);
		long distinct = pw.codePoints().distinct().count();
		if (distinct < 6)
			return WEAK; // "aaaaaaaaaaaa", "121212121212"
		if (length >= 20 || (length >= 16 && classes >= 3))
			return STRONG;
		if (length >= 14 || classes >= 3)
			return OK;
		return WEAK;
	}

	boolean acceptable()
	{
		return this != TOO_SHORT;
	}
}
