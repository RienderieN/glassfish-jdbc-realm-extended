package glassfish.security.auth.jdbc.util.factory.exceptions;

import glassfish.security.auth.jdbc.util.factory.passwordtypes.BcryptPassword;
import glassfish.security.auth.jdbc.util.factory.passwordtypes.MessageDigestPassword;
import glassfish.security.auth.jdbc.util.factory.passwordtypes.UnencryptedPassword;

/**
 * PasswordTypeException is threw by PasswordType implementations when an error was incured.
 * <p>
 * @author RienderieN
 * @version 1.0.0
 * @see BcryptPassword
 * @see MessageDigestPassword
 * @see UnencryptedPassword
 */
public class PasswordTypeException extends Exception
{

    public PasswordTypeException()
    {
        super();
    }

    public PasswordTypeException( String message )
    {
        super( message );
    }

    public PasswordTypeException( String message, Throwable cause )
    {
        super( message, cause );
    }

    public PasswordTypeException( Throwable cause )
    {
        super( cause );
    }

}
