package glassfish.security.auth.jdbc.realm;

import com.sun.appserv.security.AppservRealm;
import com.sun.enterprise.security.auth.realm.BadRealmException;
import com.sun.enterprise.security.auth.realm.InvalidOperationException;
import com.sun.enterprise.security.auth.realm.NoSuchRealmException;
import com.sun.enterprise.security.auth.realm.NoSuchUserException;
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
 * This realm includes several encryption algorithms:
 * <ul>
 * <li> <code>None</code>: user password isn't encrypted (a plaintext password).
 * <li> <code>Bcrypt</code>: user password encrypted with {@link <a href="http://www.mindrot.org/projects/jBCrypt/">jBCrypt</a>}.
 * <li> <code>SHA-256</code>, <code>SHA-1</code> or <code>MD5</code>: user password encrypted with {@link MessageDigest}.
 * </ul>
 * <p>
 * The JDBC Realm needs the following properties in its configuration:
 * <p>
 * <ul>
 * <li><b>Mandatory properties:</b>
 * <ul>
 * <li> <code>jaas-context</code>: JAAS context name used to access LoginModule for authentication (for example <i>jdbcRealmExtended</i>).
 * <li> <code>datasource-jndi</code>: datasource jndi name.
 * <li> <code>db-user</code>: datasource user name (if the datasource user name was define into the datasource jndi configuration then this
 * property isn't mandatory).
 * <li> <code>db-password</code>: datasource password (if the datasource password was define into the datasource jndi configuration then this
 * property isn't mandatory).
 * <li> <code>user-table</code>: table name containing user name and password.
 * <li> <code>user-name-column</code>: column name corresponding to user name in user-table.
 * <li> <code>password-column</code>: column name corresponding to password in user-table.
 * <li> <code>group-table</code>: table name containing group name.
 * <li> <code>group-name-column</code>: column name corresponding to group in group-table.
 * <li><code>group-table-user-name-column</code>: column name corresponding to user name in group-table
 * (this property isn't mandatory if the <code>group-table</code> property is equals to the <code>user-table</code> property).
 * </ul>
 * <p>
 * <li><b>Optional properties:</b>
 * <ul>
 * <li> <code>digest-algorithm</code>: algorithm used to encrypt user password(values: <code>None</code>, <code>Bcrypt</code>,
 * <code>SHA-256</code>, <code>SHA-1</code> or <code>MD5</code>).
 * <li> <code>password-salt</code>: plaintext password salt.
 * <li> <code>bcrypt-log-rounds</code>: {@link <a href="http://www.mindrot.org/projects/jBCrypt/">jBCrypt</a>} log rounds.
 * <li> <code>encoding</code>: encoding type (values: <code>hex</code> or <code>base64</code>).
 * <li> <code>charset</code>: {@link Charset} name.
 * </ul>
 * </ul>
 * <p>
 * <b>WARNING:</b> <br/>
 * If the <code>digest-algorithm</code> is equals to <code>None</code> value, user password isn't encrypted.<br/>
 * If the <code>digest-algorithm</code> property isn't defined, the <code>digest-algorithm</code> property will correspond
 * to the <code>default-digest-algorithm</code> property defined into the Glassfish security config (by default it's <code>SHA-256</code>).</br>
 * If the <code>default-digest-algorithm</code> property isn't defined, the <code>digest-algorithm</code> property will correspond to <code>SHA-256</code>.
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
