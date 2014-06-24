package glassfish.security.auth.jdbc.util;

import glassfish.security.auth.jdbc.util.factory.PasswordTypeFactory;
import glassfish.security.auth.jdbc.util.factory.exceptions.PasswordTypeException;
import glassfish.security.auth.jdbc.util.factory.passwordtypes.BcryptPassword;
import glassfish.security.auth.jdbc.util.factory.passwordtypes.MessageDigestPassword;
import glassfish.security.auth.jdbc.util.factory.passwordtypes.UnencryptedPassword;
import java.util.Properties;
import org.junit.Assert;
import org.junit.Test;

/**
 *
 * @author pluxz
 */
public class PasswordTypeFactoryTest
{

    @Test( expected = IllegalArgumentException.class )
    public void should_throw_illegalArgumentException()
            throws IllegalArgumentException, PasswordTypeException
    {
        Properties props = null;
        PasswordTypeFactory ptf = PasswordTypeFactory.getInstance();
        ptf.createPasswordType( props );
    }

    @Test
    public void should_return_UnencryptedPassword()
            throws Exception
    {
        Properties props = new Properties();
        props.setProperty( PasswordTypeFactory.PROPERTY.DIGEST_ALGORITHM.toString(), "none" );
        PasswordTypeFactory ptf = PasswordTypeFactory.getInstance();
        Assert.assertTrue( "Should return an unencrypted password instance", ( ptf.createPasswordType( props ) instanceof UnencryptedPassword ) );

    }

    @Test
    public void should_return_MessageDigestPassword_SHA256_byDefault()
            throws Exception
    {
        Properties props = new Properties();
        PasswordTypeFactory ptf = PasswordTypeFactory.getInstance();
        Assert.assertTrue( "Should return a MessageDigestPassword instance", ( ptf.createPasswordType( props ) instanceof MessageDigestPassword ) );
    }

    @Test
    public void should_return_MessageDigestPassword_SHA256()
            throws Exception
    {
        Properties props = new Properties();
        props.setProperty( PasswordTypeFactory.PROPERTY.DIGEST_ALGORITHM.toString(), "sha-256" );
        PasswordTypeFactory ptf = PasswordTypeFactory.getInstance();
        Assert.assertTrue( "Should return a MessageDigestPassword instance", ( ptf.createPasswordType( props ) instanceof MessageDigestPassword ) );
    }

    @Test
    public void should_return_BCryptPassword()
            throws Exception
    {
        Properties props = new Properties();
        props.setProperty( PasswordTypeFactory.PROPERTY.DEFAULT_DIGEST_ALGORITHM.toString(), "bcrypt" );
        PasswordTypeFactory ptf = PasswordTypeFactory.getInstance();
        Assert.assertTrue( "Should return a BcryptPassword instance", ( ptf.createPasswordType( props ) instanceof BcryptPassword ) );
    }

    @Test( expected = PasswordTypeException.class )
    public void should_throw_PasswordTypeException_invalid_digest()
            throws PasswordTypeException
    {
        Properties props = new Properties();
        props.setProperty( PasswordTypeFactory.PROPERTY.DEFAULT_DIGEST_ALGORITHM.toString(), "sha-257" );
        PasswordTypeFactory ptf = PasswordTypeFactory.getInstance();
        ptf.createPasswordType( props );
    }

    @Test( expected = PasswordTypeException.class )
    public void should_throw_PasswordTypeException_invalid_logRound_range()
            throws PasswordTypeException
    {
        Properties props = new Properties();
        props.setProperty( PasswordTypeFactory.PROPERTY.DEFAULT_DIGEST_ALGORITHM.toString(), "bcrypt" );
        props.setProperty( PasswordTypeFactory.PROPERTY.BCRYPT_LOG_ROUNDS.toString(), "100" );
        PasswordTypeFactory ptf = PasswordTypeFactory.getInstance();
        ptf.createPasswordType( props );
    }

    @Test( expected = PasswordTypeException.class )
    public void should_throw_PasswordTypeException_invalid_logRound_parse()
            throws PasswordTypeException
    {
        Properties props = new Properties();
        props.setProperty( PasswordTypeFactory.PROPERTY.DEFAULT_DIGEST_ALGORITHM.toString(), "bcrypt" );
        props.setProperty( PasswordTypeFactory.PROPERTY.BCRYPT_LOG_ROUNDS.toString(), "abc" );
        PasswordTypeFactory ptf = PasswordTypeFactory.getInstance();
        ptf.createPasswordType( props );
    }

    @Test( expected = PasswordTypeException.class )
    public void should_throw_PasswordTypeException_invalid_charset()
            throws PasswordTypeException
    {
        Properties props = new Properties();
        props.setProperty( PasswordTypeFactory.PROPERTY.DEFAULT_DIGEST_ALGORITHM.toString(), "sha-257" );
        props.setProperty( PasswordTypeFactory.PROPERTY.CHARSET.toString(), "UTF-9" );
        PasswordTypeFactory ptf = PasswordTypeFactory.getInstance();
        ptf.createPasswordType( props );
    }
}
