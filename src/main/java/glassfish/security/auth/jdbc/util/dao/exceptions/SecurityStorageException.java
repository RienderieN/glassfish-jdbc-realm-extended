package glassfish.security.auth.jdbc.util.dao.exceptions;

/**
 * SecurityStorageException class is threw by SecurityStorage class when an error was incured.
 * <p>
 * @author RienderieN
 * @version 1.0.0
 */
public class SecurityStorageException extends Exception
{

    public SecurityStorageException()
    {
        super();
    }

    public SecurityStorageException( String message )
    {
        super( message );
    }

    public SecurityStorageException( String message, Throwable cause )
    {
        super( message, cause );
    }

    public SecurityStorageException( Throwable cause )
    {
        super( cause );
    }

}
