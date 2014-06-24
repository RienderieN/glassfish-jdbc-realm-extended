package glassfish.security.auth.jdbc.login;

import com.sun.appserv.security.AppservPasswordLoginModule;
import com.sun.enterprise.util.i18n.StringManagerBase;
import glassfish.security.auth.jdbc.realm.JDBCRealmExtended;
import java.util.Arrays;
import java.util.logging.Logger;
import javax.security.auth.login.LoginException;

/**
 * The JDBCLoginModuleExtended implements a JDBC Login module for Glassfish.
 * <p>
 * @author RienderieN
 * @version 1.0.0
 * @see JDBCRealmExtended
 */
public class JDBCLoginModuleExtended extends AppservPasswordLoginModule
{

    private final StringManagerBase jdbclmeSm = StringManagerBase.getStringManager( JDBCLoginModuleExtended.class.getSimpleName(),
            JDBCLoginModuleExtended.class.getClassLoader() );

    @Override
    protected void authenticateUser()
            throws LoginException
    {
        String msg = null;
        if ( !( getCurrentRealm() instanceof JDBCRealmExtended ) ) {
            msg = jdbclmeSm.getString( "jdbclm.authenticateuser.badrealm.exception",
                    JDBCLoginModuleExtended.class.getName(), JDBCRealmExtended.class.getName(),
                    JDBCLoginModuleExtended.class.getName() + ".authenticateUser()" );
            throw new LoginException( msg );
        }

        final JDBCRealmExtended jdbcRealm = ( JDBCRealmExtended ) getCurrentRealm();
        if ( getUsername() == null || getUsername().trim().isEmpty() ) {
            msg = jdbclmeSm.getString( "jdbclm.authenticateuser.nulluser.exception",
                    JDBCLoginModuleExtended.class.getName() + ".authenticateUser()" );
            throw new LoginException( msg );
        }

        final String[] grpList = jdbcRealm.authenticate( getUsername(), String.valueOf( getPasswordChar() ) );
        if ( grpList == null || grpList.length == 0 ) {
            msg = jdbclmeSm.getString( "jdbclm.authenticateuser.loginfail.exception",
                    getUsername(),
                    JDBCLoginModuleExtended.class.getName() + ".authenticateUser()" );
            throw new LoginException( msg );
        }

        msg = jdbclmeSm.getString( "jdbclm.authenticateuser.loginsucc.info.log",
                getUsername(), Arrays.toString( grpList ),
                JDBCLoginModuleExtended.class.getName() + ".authenticateUser()" );
        Logger.getLogger( JDBCLoginModuleExtended.class.getName() ).info( msg );

        commitUserAuthentication( grpList );
    }
}
