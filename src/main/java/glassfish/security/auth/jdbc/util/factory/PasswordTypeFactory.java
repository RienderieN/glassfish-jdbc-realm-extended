package glassfish.security.auth.jdbc.util.factory;

import glassfish.security.auth.jdbc.util.factory.exceptions.PasswordTypeException;
import glassfish.security.auth.jdbc.util.factory.passwordtypes.BcryptPassword;
import glassfish.security.auth.jdbc.util.factory.passwordtypes.IPasswordType;
import glassfish.security.auth.jdbc.util.factory.passwordtypes.MessageDigestPassword;
import glassfish.security.auth.jdbc.util.factory.passwordtypes.UnencryptedPassword;
import java.nio.charset.Charset;
import java.util.Properties;

/**
 * PasswordTypeFactory class allows to create and return a {@link IPasswordType} implementation
 * ({@link BcryptPassword}, {@link MessageDigestPassword}, {@link UnencryptedPassword})
 * according to the specified properties.
 * <p>
 * Optional properties:
 * <ul>
 * <li> <code>digest-algorithm</code>: the algorithm used to encrypt user password(values: none, bcrypt, SHA-256, SHA-1 or MD5).
 * <li> <code>password-salt</code>: the plaintext salt to append to a user plaintext password.
 * <li> <code>bcrypt-log-rounds</code>: the {@link <a href="http://www.mindrot.org/projects/jBCrypt/">Bcrypt</a>} log rounds.
 * <li> <code>encoding</code>: the encoding type (values:hex or base64).
 * <li> <code>charset</code>: the {@link Charset} name.
 * </ul>
 * <p>
 * <b>WARNING:</b> <br/>
 * If the digest-algorithm is equals to 'none' value, user password won't be encrypted into the database. If
 * the digest-algorithm property isn't defined, the digest-algorithm property will correspond
 * to the default-digest-algorithm property defined into the glassfish security config (by default it's 'SHA-256').
 * If the default-digest-algorithm property isn't defined, the digest-algorithm property will correspond to SHA-256.
 * <p>
 * @author RienderieN
 * @version 1.0.0
 * @see IPasswordType
 * @see BcryptPassword
 * @see MessageDigestPassword
 * @see UnencryptedPassword
 */
public class PasswordTypeFactory
{

    /**
     * PasswordTypeFactory properties enumeration.
     */
    public static enum PROPERTY
    {

        DEFAULT_DIGEST_ALGORITHM( "default-digest-algorithm" ),
        DIGEST_ALGORITHM( "digest-algorithm" ),
        PASSWORD_SALT( "password-salt" ),
        BCRYPT_LOG_ROUNDS( "bcrypt-log-rounds" ),
        ENCODING( "encoding" ),
        CHARSET( "charset" );

        private String name;

        PROPERTY( String name )
        {
            this.name = name;
        }

        @Override
        public String toString()
        {
            return name;
        }

    }

    /**
     * value: {@value }.
     */
    public final static String BCRYPT = "bcrypt";

    /**
     * value: {@value }.
     */
    public final static String NONE = "none";

    /**
     * A PasswordTypeFactory instance.
     */
    private static volatile PasswordTypeFactory instance = null;

    private PasswordTypeFactory()
    {
    }

    /**
     * Create and return a {@link IPasswordType} implementation ({@link BcryptPassword},
     * {@link MessageDigestPassword} or {@link UnencryptedPassword}) according to
     * the specified arguments.
     * <p>
     * @param properties A set of properties.
     * @return A IPasswordType implementation.
     * @throws PasswordTypeException If the {@link Properties} object is null,
     *                               if a property is missing or invalid.
     */
    public IPasswordType createPasswordType( Properties properties )
            throws PasswordTypeException
    {
        if ( properties == null ) {
            throw new IllegalArgumentException( "properties arguement cannot be null" );
        }

        IPasswordType passwordType = null;
        final String algorithm = properties.getProperty( PROPERTY.DIGEST_ALGORITHM.toString(), properties.getProperty( PROPERTY.DEFAULT_DIGEST_ALGORITHM.toString() ) );
        final String salt = properties.getProperty( PROPERTY.PASSWORD_SALT.toString() );
        final String charset = properties.getProperty( PROPERTY.CHARSET.toString() );
        final String encoding = properties.getProperty( PROPERTY.ENCODING.toString() );
        final String bcryptLogRounds = properties.getProperty( PROPERTY.BCRYPT_LOG_ROUNDS.toString() );

        if ( NONE.equalsIgnoreCase( algorithm ) ) {
            passwordType = new UnencryptedPassword( salt, charset, encoding );
        } else if ( BCRYPT.equalsIgnoreCase( algorithm ) ) {
            passwordType = new BcryptPassword( salt, bcryptLogRounds );
        } else {
            passwordType = new MessageDigestPassword( algorithm, salt, charset, encoding );
        }
        return passwordType;
    }

    /**
     * Create and return a PasswordTypeFactory instance.
     * <p>
     * @return A PasswordTypeFactory instance
     */
    public static PasswordTypeFactory getInstance()
    {
        if ( PasswordTypeFactory.instance == null ) {
            synchronized ( PasswordTypeFactory.class ) {
                if ( PasswordTypeFactory.instance == null ) {
                    PasswordTypeFactory.instance = new PasswordTypeFactory();
                }
            }
        }
        return PasswordTypeFactory.instance;
    }
}
