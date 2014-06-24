package glassfish.security.auth.jdbc.util.factory.passwordtypes;

import glassfish.security.auth.jdbc.util.factory.exceptions.PasswordTypeException;
import java.nio.charset.Charset;
import javax.xml.bind.DatatypeConverter;

/**
 * UnencryptedPassword class is just the representation of an unencrypted password.
 * <p>
 * @author RienderieN
 * @version 1.0.0
 * @see MessageDigestPassword
 * @see BcryptPassword
 */
public class UnencryptedPassword implements IPasswordType
{

    /**
     * value: {@value}.
     */
    public final static String HEX = "hex";
    /**
     * value: {@value}.
     */
    public final static String BASE64 = "base64";

    private final Charset charset;
    // encoding to use (Hex or Base64).
    private final String encoding;
    // The plaintext salt to append to a plaintext password.
    private final String salt;

    /**
     * @param salt     A plaintext salt to append to a plaintext password.
     *                 May be <code>null</code>.
     * @param charset  A {@link Charset} name to use.
     *                 May be <code>null</code>
     * @param encoding An encoding type to use.
     *                 May be <code>{@link #HEX hex}</code>,
     *                 <code>{@link #BASE64 base64}</code>
     *                 or <code>null</code>.
     */
    public UnencryptedPassword( final String salt, final String charset, final String encoding )
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

        Charset charsetType = null;
        try {
            charsetType = Charset.forName( charset );
        } catch ( IllegalArgumentException ex ) {
            charsetType = Charset.defaultCharset();
        } finally {
            this.charset = charsetType;
        }

        this.encoding = encoding;

    }

    public UnencryptedPassword()
            throws PasswordTypeException
    {
        this( null, null, null );
    }

    @Override
    public String encryptPassword( final String password )
    {
        byte[] hashedPasswd = null;

        hashedPasswd = password.concat( salt ).getBytes( charset );

        if ( BASE64.equalsIgnoreCase( encoding ) ) {
            return base64Encode( hashedPasswd );
        } else if ( HEX.equalsIgnoreCase( encoding ) ) {
            return hexEncode( hashedPasswd );
        } else {
            return new String( hashedPasswd, charset );
        }
    }

    @Override
    public boolean checkPassword( final String plainPassword, final String hashedPassword )
    {
        return hashedPassword.equals( encryptPassword( plainPassword ) );
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
