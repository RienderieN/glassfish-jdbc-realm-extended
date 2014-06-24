package glassfish.security.auth.jdbc.util.factory.passwordtypes;

import glassfish.security.auth.jdbc.util.factory.PasswordTypeFactory;

/**
 * IPasswordType interface corresponding to a password encryption type instancied
 * and returned by {@link PasswordTypeFactory}.
 * <p>
 * @author RienderieN
 * @version 1.0.0
 */
public interface IPasswordType
{

    /**
     * Encrypt a plaintext password and return it.
     * <p>
     * @param password A plaintext password to encrypt
     * @return A encrypted password
     */
    String encryptPassword( final String password );

    /**
     * Check that a plaintext password matches a previously encrypted one.
     * <p>
     * @param plainPassword  A plaintext password to check.
     * @param hashedPassword A previously encrypted password.
     * @return <code>true</code> if the the passwords match,
     *         <code>false</code> otherwise.
     */
    boolean checkPassword( final String plainPassword, final String hashedPassword );
}
