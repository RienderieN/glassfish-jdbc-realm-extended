package glassfish.security.auth.jdbc.util.factory.passwordtypes;

import glassfish.security.auth.jdbc.util.factory.exceptions.PasswordTypeException;
import java.security.SecureRandom;
import org.mindrot.jbcrypt.BCrypt;

/**
 * BcryptPassword class allows to encrypt a plaintext password with the
 * {@link <a href="http://www.mindrot.org/projects/jBCrypt/">Bcrypt</a>}
 * algorithm and check that a plaintext password matches a previously encrypted one.
 * <p>
 * @author RienderieN
 * @version 1.0.0
 * @see MessageDigestPassword
 * @see UnencryptedPassword
 */
public class BcryptPassword implements IPasswordType
{

    /**
     * The minimum {@link <a href="http://www.mindrot.org/projects/jBCrypt/">Bcrypt</a>} log
     * rounds allowed (value: {@value}).
     */
    public static final int MIN_LOG_ROUNDS = 4;
    /**
     * The maximum {@link <a href="http://www.mindrot.org/projects/jBCrypt/">Bcrypt</a>} log
     * rounds allowed (value: {@value}).
     */
    public static final int MAX_LOG_ROUNDS = 31;
    /**
     * The default {@link <a href="http://www.mindrot.org/projects/jBCrypt/">Bcrypt</a>} log
     * round, if the log round argument isn't informed (value: {@value}).
     */
    public static final int DEFAULT_LOG_ROUNDS = 8;

    // The salt generate by Bcrypt.gensalt method
    private final String bcryptSalt;
    // The salt to append to a plaintext password
    private final String salt;

    /**
     * Creates a BcryptPassword instance with the specified arguments.
     * <p>
     * @param salt         A plaintext salt to concat to a plaintext password.
     *                     May be <code>null</code>.
     * @param logRound     A number of rounds of hashing to apply.
     *                     May be <code>null</code>.
     * @param secureRandom An instance of {@link java.security.SecureRandom}.
     *                     May be <code>null</code>.
     * @throws PasswordTypeException if the logRound argument cannot be parsed to an integer,
     *                               if the logRound argument isn't between
     *                               {@link BcryptPassword#MIN_LOG_ROUNDS} and
     *                               {@link BcryptPassword#MAX_LOG_ROUNDS} range.
     */
    public BcryptPassword( final String salt, final String logRound, final SecureRandom secureRandom )
            throws PasswordTypeException
    {
        /*
         * need to define the salt parameter to an empty String to avoid to
         * throw a NullPointerException with the concat method.
         */
        if ( salt != null && !salt.trim().isEmpty() ) {
            this.salt = salt;
        } else {
            this.salt = "";
        }

        Integer logRoundType = null;
        try {
            if ( logRound == null || logRound.trim().isEmpty() ) {
                logRoundType = DEFAULT_LOG_ROUNDS;
            } else {
                logRoundType = Integer.parseInt( logRound );
            }
        } catch ( NumberFormatException ex ) {
            throw new PasswordTypeException( "logRound argument isn't a valid integer" );
        }

        if ( logRoundType < BcryptPassword.MIN_LOG_ROUNDS || logRoundType > BcryptPassword.MAX_LOG_ROUNDS ) {
            throw new PasswordTypeException( "Range Bcrypt's log round must be between " + MIN_LOG_ROUNDS + " and " + MAX_LOG_ROUNDS );
        }

        if ( secureRandom != null ) {
            this.bcryptSalt = BCrypt.gensalt( logRoundType, secureRandom );
        } else {
            this.bcryptSalt = BCrypt.gensalt( logRoundType );
        }

    }

    /**
     * Creates a BcryptPassword instance with the specified arguments.
     * <p>
     * @param salt     A plaintext salt to concat to a plaintext password.
     *                 May be <code>null</code>.
     * @param logRound A number of rounds of hashing to apply.
     *                 May be <code>null</code>.
     * @throws PasswordTypeException if the logRound arguments isn't between
     *                               {@link BcryptPassword#MIN_LOG_ROUNDS} and
     *                               {@link BcryptPassword#MAX_LOG_ROUNDS}.
     */
    public BcryptPassword( final String salt, final String logRound )
            throws PasswordTypeException
    {
        this( salt, logRound, null );
    }

    public BcryptPassword()
            throws PasswordTypeException
    {
        this( null, null );
    }

    @Override
    public String encryptPassword( final String password )
    {
        return BCrypt.hashpw( password.concat( salt ), bcryptSalt );
    }

    @Override
    public boolean checkPassword( final String plainPassword, final String hashedPassword )
    {
        return BCrypt.checkpw( plainPassword.concat( salt ), hashedPassword );
    }

}
