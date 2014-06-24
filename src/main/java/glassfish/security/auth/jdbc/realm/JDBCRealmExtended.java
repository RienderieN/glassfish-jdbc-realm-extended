package glassfish.security.auth.jdbc.realm;

import com.sun.appserv.security.AppservRealm;
import com.sun.enterprise.security.auth.realm.BadRealmException;
import com.sun.enterprise.security.auth.realm.InvalidOperationException;
import com.sun.enterprise.security.auth.realm.NoSuchRealmException;
import com.sun.enterprise.security.auth.realm.NoSuchUserException;
import com.sun.enterprise.security.auth.realm.jdbc.JDBCRealm;
import com.sun.enterprise.util.i18n.StringManagerBase;
import glassfish.security.auth.jdbc.login.JDBCLoginModuleExtended;
import glassfish.security.auth.jdbc.util.dao.SecurityStorage;
import glassfish.security.auth.jdbc.util.dao.exceptions.SecurityStorageException;
import glassfish.security.auth.jdbc.util.factory.PasswordTypeFactory;
import glassfish.security.auth.jdbc.util.factory.exceptions.PasswordTypeException;
import glassfish.security.auth.jdbc.util.factory.passwordtypes.IPasswordType;
import java.nio.charset.Charset;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Collections;
import java.util.Enumeration;
import java.util.Properties;
import java.util.logging.Level;
import org.jvnet.hk2.annotations.Service;

/**
 * Glassfish realm supporting JDBC authentication.
 * <p>
 * The realm JDBCRealmExtended is an alternative of the realm {@link JDBCRealm} and
 * includes several encryption type:
 * <ul>
 * <li> <code>None</code>: the user password won't be encrypted (a plaintext password).
 * <li> <code>SHA-256, SHA-1 or MD5</code>: the user password will be encrypted with {@link MessageDigest}.
 * <li> <code>Bcrypt</code>: the user password will be encrypt with {@link <a href="http://www.mindrot.org/projects/jBCrypt/">JBcrypt</a>}.
 * </ul>
 * <p>
 * The JDBC Realm needs the following properties in its configuration:
 * <p>
 * <ul>
 * <li>Mandatory properties:
 * <ul>
 * <li> <code>jaas-context</code>: JAAS context name used to access to the
 * LoginModule for authentication (ex: jdbcRealmExtended).
 * <li> <code>datasource-jndi</code>: the datasource jndi name.
 * <li> <code>db-user</code>: the datasource user name (if the datasource
 * user name was define into the datasource jndi configuration then this
 * parameter isn't mandatory).
 * <li> <code>db-password</code>: the datasource password (if the datasource
 * password was define into the datasource jndi configuration then this
 * parameter isn't mandatory).
 * <li> <code>user-table</code>: the table name containing user name and password.
 * <li> <code>user-name-column</code>: the column name corresponding to user name in user-table and group-table.
 * <li> <code>password-column</code>: the column name corresponding to password in user-table.
 * <li> <code>group-table</code>: the table name containing user name and group name.
 * <li> <code>group-name-column</code>: the column name corresponding to group in group-table.
 * <li><code>group-table-user-name-column</code>: the column name corresponding to user name in group-table
 * (this property isn't mandatory if the group-table property is equals to the user-table property).
 * </ul>
 * <p>
 * <li>Optional properties:
 * <ul>
 * <li> <code>digest-algorithm</code>: the algorithm used to encrypt user password(values: none, bcrypt, SHA-256, SHA-1 or MD5).
 * <li> <code>password-salt</code>: the plaintext salt to append to a user plaintext password.
 * <li> <code>bcrypt-log-rounds</code>: the {@link <a href="http://www.mindrot.org/projects/jBCrypt/">Bcrypt</a>} log rounds.
 * <li> <code>encoding</code>: the encoding type (values: hex or base64).
 * <li> <code>charset</code>: the {@link Charset} name.
 * </ul>
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
 * @see JDBCLoginModuleExtended
 * @see PasswordTypeFactory
 * @see JDBCLoginModuleExtended
 */
@Service( name = "JdbcRealmExtended" )
public class JDBCRealmExtended extends AppservRealm
{

    /**
     * Descriptive string of the authentication type of this realm.
     */
    final static String AUTH_TYPE = "jdbc realm extended";

    private IPasswordType passwordType;
    private SecurityStorage securityStorage;

    private final StringManagerBase jdbcreSm = StringManagerBase.getStringManager( JDBCRealmExtended.class.getSimpleName(),
            JDBCRealmExtended.class.getClassLoader() );

    public JDBCRealmExtended()
    {
    }

    /**
     * @param passwordType    A {@link IPasswordType}.
     * @param securityStorage A {@link SecurityStorage}.
     */
    public JDBCRealmExtended( IPasswordType passwordType, SecurityStorage securityStorage )
    {
        this.passwordType = passwordType;
        this.securityStorage = securityStorage;
    }

    @Override
    protected void init( Properties props )
            throws BadRealmException, NoSuchRealmException
    {
        super.init( props );

        final String jaasCtx = props.getProperty( AppservRealm.JAAS_CONTEXT_PARAM );

        String msg = null;
        if ( jaasCtx == null || jaasCtx.trim().isEmpty() ) {
            msg = log( Level.SEVERE, "jdbcrealm.init.missingprop.exception",
                    AppservRealm.JAAS_CONTEXT_PARAM, JDBCRealmExtended.class.getName() + ".init" );
            throw new BadRealmException( msg );
        }
        this.setProperty( AppservRealm.JAAS_CONTEXT_PARAM, jaasCtx );

        try {
            passwordType = PasswordTypeFactory.getInstance().createPasswordType( props );
        } catch ( IllegalArgumentException | PasswordTypeException ex ) {
            throw new BadRealmException( ex );
        }

        try {
            securityStorage = new SecurityStorage( props );
        } catch ( SecurityStorageException ex ) {
            throw new BadRealmException( ex );
        }

    }

    @Override
    public String getAuthType()
    {
        return JDBCRealmExtended.AUTH_TYPE;
    }

    @Override
    public Enumeration<String> getGroupNames( final String username )
            throws InvalidOperationException, NoSuchUserException
    {
        return Collections.enumeration( Arrays.asList( securityStorage.findGroupNames( username ) ) );

    }

    /**
     * Anthenticate a user with a username and password and return groups belonging.
     * <p>
     * @param username A username.
     * @param password A user plaintext password.
     * @return A string array of groups belonging to a username,
     *         If the user isn't authenticate it return an empty string array.
     */
    public String[] authenticate( final String username, final String password )
    {
        final boolean isAuthenticated = passwordType.checkPassword( password, securityStorage.findPassword( username ) );
        final String[] groups = isAuthenticated ? securityStorage.findGroupNames( username ) : null;
        return groups;
    }

    /**
     * Returns a localized string.
     * <p>
     * @param level    A logging level.
     * @param key      A name of a resource bundle to fetch.
     * @param messVals A set of arguments to provide to the resource bundle.
     * @return A formatted localized string.
     */
    private String log( final Level level, final String key, Object... messVals )
    {
        String message = jdbcreSm.getString( key, messVals );
        if ( _logger.isLoggable( level ) ) {
            _logger.log( level, message );
        }
        return message;
    }

}
