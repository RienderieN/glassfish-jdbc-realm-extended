package glassfish.security.auth.jdbc.util.factory.passwordtypes;

import glassfish.security.auth.jdbc.util.factory.exceptions.PasswordTypeException;
import java.nio.charset.Charset;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import javax.xml.bind.DatatypeConverter;

/**
 * MessageDigestPassword class allows to encrypt a plaintext password with the
 * {@link MessageDigest} class and checks that a plaintext password matches a
 * previously encrypted one.
 * <p>
 * @author RienderieN
 * @version 1.0.0
 * @see BcryptPassword
 * @see UnencryptedPassword
 */
public class MessageDigestPassword implements IPasswordType
{

    /**
     * value: {@value }.
     */
    public final static String HEX = "hex";
    /**
     * value: {@value }.
     */
    public final static String BASE64 = "base64";

    /**
     * The default digest used if the digestAlgorithm argument is null or empty.
     */
    public final static String DEFAULT_DIGEST = "SHA-256";

    private final MessageDigest md;
    private final Charset charset;
    // encoding to use (Hex or Base64).
    private final String encoding;
    // The plaintext salt to append to a plaintext password.
    private final String salt;

    /**
     * Creates a MessageDigestPassword instance with the specified arguments.
     * <p>
     * @param digestAlgorithm A {@link MessageDigest} algorithm to use.
     * @param salt            A plaintext salt to append to a plaintext password.
     *                        May be <code>null</code>.
     * @param charset         A {@link Charset} name to use.
     *                        May be <code>null</code>.
     * @param encoding        An encoding type to use.
     *                        May be <code>{@link #HEX hex}</code>,
     *                        <code>{@link #BASE64 base64}</code> or
     *                        <code>null</code>.
     * @throws PasswordTypeException If the digestAlgorithm argument value isn't corresponded to the standard
     *                               {@link MessageDigest#getInstance(java.lang.String) MessageDigest} algorithms.
     */
    public MessageDigestPassword( String digestAlgorithm, final String salt, final String charset, final String encoding )
            throws PasswordTypeException
    {
        try {
            if ( digestAlgorithm == null || digestAlgorithm.trim().isEmpty() ) {
                digestAlgorithm = DEFAULT_DIGEST;
            }
            md = MessageDigest.getInstance( digestAlgorithm );
        } catch ( NoSuchAlgorithmException ex ) {
            throw new PasswordTypeException( ex );
        }

        /*
         * need to define the salt parameter to an empty String to avoid to
         * throw a NullPointerException with the concat method.
         */
        if ( salt != null && !salt.trim().isEmpty() ) {
            this.salt = salt;
        } else {
            this.salt = "";
        }

        Charset charsetType = null;
        try {
            charsetType = Charset.forName( charset );
        } catch ( IllegalArgumentException ex ) {
            charsetType = Charset.defaultCharset();
        } finally {
            this.charset = charsetType;
        }

        if ( encoding != null && !encoding.trim().isEmpty() ) {
            this.encoding = encoding;
        } else {
            this.encoding = HEX;
        }
    }

    /**
     * Creates a MessageDigestPassword instance with the specified arguments.
     * <p>
     * @param digestAlgorithm A {@link MessageDigest} algorithm to use.
     * @param salt            A plaintext salt to append to a plaintext password.
     *                        May be <code>null</code>.
     * @throws PasswordTypeException If the digestAlgorithm argument value isn't corresponded to the standard
     *                               {@link MessageDigest#getInstance(java.lang.String) MessageDigest} algorithms.
     */
    public MessageDigestPassword( final String digestAlgorithm, final String salt )
            throws PasswordTypeException
    {
        this( digestAlgorithm, salt, null, null );
    }

    /**
     * Creates a MessageDigestPassword instance with the specified arguments.
     * <p>
     * @param digestAlgorithm A {@link MessageDigest} algorithm to use.
     * @throws PasswordTypeException If the digestAlgorithm argument value isn't corresponded to the standard
     *                               {@link MessageDigest#getInstance(java.lang.String) MessageDigest} algorithms.
     */
    public MessageDigestPassword( final String digestAlgorithm )
            throws PasswordTypeException
    {
        this( digestAlgorithm, null, null, null );
    }

    @Override
    public String encryptPassword( final String password )
    {
        byte[] hashedPasswd = null;

        hashedPasswd = password.concat( salt ).getBytes( charset );
        md.reset();
        hashedPasswd = md.digest( hashedPasswd );

        // by default encode the hashed password with hex
        if ( BASE64.equalsIgnoreCase( encoding ) ) {
            return base64Encode( hashedPasswd );
        } else {
            return hexEncode( hashedPasswd );
        }
    }

    @Override
    public boolean checkPassword( final String plainPassword, final String hashedPassword )
    {
        String hashedPlainPassword = this.encryptPassword( plainPassword );
        return hashedPassword.equals( hashedPlainPassword );
    }

    /**
     * Encode a byte array of a password into Base64 string.
     * <p>
     * @param password The byte array of a password.
     * @return A string encoded into Base 64.
     */
    private String base64Encode( final byte[] password )
    {
        return DatatypeConverter.printBase64Binary( password );
    }

    /**
     * Encode a byte array of a password into Hexadecimal string.
     * <p>
     * @param password A byte array of a password.
     * @return A string encoded into hexadecimal.
     */
    private String hexEncode( final byte[] password )
    {
        return DatatypeConverter.printHexBinary( password );
    }

}
