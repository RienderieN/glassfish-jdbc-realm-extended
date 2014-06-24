package glassfish.security.auth.jdbc.util.dao;

import com.sun.enterprise.util.i18n.StringManagerBase;
import glassfish.security.auth.jdbc.realm.JDBCRealmExtended;
import glassfish.security.auth.jdbc.util.dao.exceptions.SecurityStorageException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.naming.Context;
import javax.naming.InitialContext;
import javax.naming.NamingException;
import javax.sql.DataSource;

/**
 * SecurityStorage class is a Database abstraction for a User and a Group Table used with Glassfish.
 * <p>
 * Mandatory propeties:
 * <ul>
 * <li> <code>datasource-jndi</code>: the datasource jndi name.
 * <li> <code>db-user</code>: the datasource user name (if the datasource
 * user name was define into the datasource jndi configuration then this
 * property isn't mandatory).
 * <li> <code>db-password</code>: the datasource password (if the datasource
 * password was define into the datasource jndi configuration then this
 * property isn't mandatory).
 * <li> <code>user-table</code>: the table name containing user name and password.
 * <li> <code>user-name-column</code>: the column name corresponding to user name in user-table and group-table.
 * <li> <code>password-column</code>: the column name corresponding to password in user-table.
 * <li> <code>group-table</code>: the table name containing user name and group name.
 * <li> <code>group-name-column</code>: the column name corresponding to group in group-table.
 * <li><code>group-table-user-name-column</code>: the column name corresponding to user name in group-table
 * (this property isn't mandatory if the group-table property is equals to the user-table property).
 * </ul>
 * <p>
 * @author RienderieN
 * @version 1.0.0
 */
public class SecurityStorage
{

    /**
     * SecurityStorage properties enumeration
     */
    public static enum PROPERTY
    {

        DATASOURCE_JNDI( "datasource-jndi" ),
        DATABASE_USER( "db-user" ),
        DATABASE_PASSWORD( "db-password" ),
        USER_TABLE( "user-table" ),
        USER_NAME_COLUMN( "user-name-column" ),
        USER_PASSWORD_COLUMN( "user-password-column" ),
        GROUP_TABLE( "group-table" ),
        GROUP_NAME_COLUMN( "group-name-column" ),
        GROUP_USER_NAME_COLUMN( "group-table-user-name-column" );

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
     * The property name corresponding to the formated query USER_PASSWORD_QUERY_FORMAT (value:{@value }).
     */
    final static String USER_PASSWORD_QUERY_PROPERTY = "user-password-query";
    /**
     * The property name corresponding to the formated query USER_GROUPS_QUERY_FORMAT (value:{@value }).
     */
    final static String USER_GROUPS_QUERY_PROPERTY = "user-groups-query";
    /**
     * The formated query to find a password according to a username (ex: SELECT PASSWORD FROM USER WHERE USERNAME = 'SuperMario').
     */
    final static String USER_PASSWORD_QUERY_FORMAT = "SELECT %1$s FROM %2$s WHERE %3$s = ?";
    /**
     * The formated query to find user groups according to a username (ex: SELECT GROUP_NAME FROM GROUP WHERE USERNAME = 'SuperMario').
     */
    final static String USER_GROUPS_QUERY_FORMAT = "SELECT %1$s FROM %2$s WHERE %3$s = ?";

    private final StringManagerBase secStorSm = StringManagerBase.getStringManager( SecurityStorage.class.getSimpleName(), SecurityStorage.class.getClassLoader() );
    protected Properties properties;

    /**
     * @param properties A set of properties.
     * @throws SecurityStorageException If Properties object is null,
     *                                  if a mandatory property is missing or invalid.
     */
    public SecurityStorage( Properties properties )
            throws SecurityStorageException
    {
        if ( properties == null ) {
            throw new SecurityStorageException( "properties argument cannot be null" );

        }
        this.properties = properties;
        checkMandatoryProperties();
        formatJDBCQueries();
    }

    /**
     * Check the validity of mandatory properties.
     * <p>
     * @throws SecurityStorageException If a mandatory property is missing.
     */
    protected void checkMandatoryProperties()
            throws SecurityStorageException
    {
        final String jndi = properties.getProperty( PROPERTY.DATASOURCE_JNDI.toString() );
        final String userTable = properties.getProperty( PROPERTY.USER_TABLE.toString() );
        final String userNameColumn = properties.getProperty( PROPERTY.USER_NAME_COLUMN.toString() );
        final String userPasswordColumn = properties.getProperty( PROPERTY.USER_PASSWORD_COLUMN.toString() );
        final String groupTable = properties.getProperty( PROPERTY.GROUP_TABLE.toString() );
        final String groupNameColumn = properties.getProperty( PROPERTY.GROUP_NAME_COLUMN.toString() );

        String msg;
        if ( jndi == null || jndi.trim().isEmpty() ) {
            msg = log( Level.SEVERE, "securitystorage.missingprop.exception",
                    PROPERTY.DATASOURCE_JNDI, SecurityStorage.class.getName() + ".checkMandatoryProperties" );
            throw new SecurityStorageException( msg );
        }

        if ( userTable == null || userTable.trim().isEmpty() ) {
            msg = log( Level.SEVERE, "securitystorage.missingprop.exception",
                    PROPERTY.USER_TABLE, SecurityStorage.class.getName() + ".checkMandatoryProperties" );
            throw new SecurityStorageException( msg );
        }

        if ( userNameColumn == null || userNameColumn.trim().isEmpty() ) {
            msg = log( Level.SEVERE, "securitystorage.missingprop.exception",
                    PROPERTY.USER_NAME_COLUMN, SecurityStorage.class.getName() + ".checkMandatoryProperties" );
            throw new SecurityStorageException( msg );
        }

        if ( userPasswordColumn == null || userPasswordColumn.trim().isEmpty() ) {
            msg = log( Level.SEVERE, "securitystorage.missingprop.exception",
                    PROPERTY.USER_PASSWORD_COLUMN, SecurityStorage.class.getName() + ".checkMandatoryProperties" );
            throw new SecurityStorageException( msg );
        }

        if ( groupTable == null || groupTable.trim().isEmpty() ) {
            msg = log( Level.SEVERE, "securitystorage.missingprop.exception",
                    PROPERTY.GROUP_TABLE, SecurityStorage.class.getName() + ".checkMandatoryProperties" );
            throw new SecurityStorageException( msg );
        }

        if ( groupNameColumn == null || groupNameColumn.trim().isEmpty() ) {
            msg = log( Level.SEVERE, "securitystorage.missingprop.exception",
                    PROPERTY.GROUP_NAME_COLUMN, SecurityStorage.class.getName() + ".checkMandatoryProperties" );
            throw new SecurityStorageException( msg );
        }
    }

    /**
     * Format the JDBC queries according to the user-table, user-name-column, user-password-column,
     * group-table, group-name-column and group-table-user-name-column properties.
     */
    protected void formatJDBCQueries()
    {
        final String userPasswordColumn = properties.getProperty( PROPERTY.USER_PASSWORD_COLUMN.toString() );
        final String userNameColumn = properties.getProperty( PROPERTY.USER_NAME_COLUMN.toString() );
        final String userTable = properties.getProperty( PROPERTY.USER_TABLE.toString() );
        final String groupNameColumn = properties.getProperty( PROPERTY.GROUP_NAME_COLUMN.toString() );
        final String groupUserNameColumn = properties.getProperty( PROPERTY.GROUP_USER_NAME_COLUMN.toString() );
        final String groupTable = properties.getProperty( PROPERTY.GROUP_TABLE.toString() );

        // format the query to get the user password
        properties.setProperty( USER_PASSWORD_QUERY_PROPERTY, String.format( USER_PASSWORD_QUERY_FORMAT, userPasswordColumn, userTable, userNameColumn ) );

        // format the query to get the user groups
        if ( groupUserNameColumn != null && !groupUserNameColumn.trim().isEmpty() ) {
            properties.setProperty( USER_GROUPS_QUERY_PROPERTY,
                    String.format( USER_GROUPS_QUERY_FORMAT, groupNameColumn, groupTable, groupUserNameColumn ) );
        } else {
            properties.setProperty( USER_GROUPS_QUERY_PROPERTY,
                    String.format( USER_GROUPS_QUERY_FORMAT, groupNameColumn, groupTable, userNameColumn ) );
        }
    }

    /**
     * Find a user password.
     * <p>
     * @param username A user name.
     * @return A user password.
     */
    public String findPassword( final String username )
    {
        Connection connection = null;
        PreparedStatement stmt = null;
        ResultSet resultset = null;
        String password = null;

        try {
            connection = this.getConection();
            stmt = connection.prepareStatement( properties.getProperty( USER_PASSWORD_QUERY_PROPERTY ) );
            stmt.setString( 1, username );
            resultset = stmt.executeQuery();
            if ( resultset.next() ) {
                password = resultset.getString( 1 );
            }
        } catch ( SQLException ex ) {
            log( Level.SEVERE, "securitystorage.getPassword.sql.exception",
                    username, JDBCRealmExtended.class.getName() + ".getPassword" );
            ex.printStackTrace();
        } finally {
            close( connection, stmt, resultset );
            return password;
        }

    }

    /**
     * Find and return groups which a user name belongs to.
     * <p>
     * @param username A user name.
     * @return A string array of groups belonging to a user name.
     */
    public String[] findGroupNames( final String username )
    {
        Connection connection = null;
        PreparedStatement stmt = null;
        ResultSet resultSet = null;
        List<String> groups = new ArrayList<>();

        try {
            connection = this.getConection();
            stmt = connection.prepareStatement( properties.getProperty( USER_GROUPS_QUERY_PROPERTY ) );
            stmt.setString( 1, username );
            resultSet = stmt.executeQuery();

            while ( resultSet.next() ) {
                groups.add( resultSet.getString( 1 ) );
            }
        } catch ( SQLException ex ) {
            log( Level.SEVERE, "securitystorage.findgroupnames.sql.exception",
                    username, JDBCRealmExtended.class.getName() + ".findGroupNames" );
            ex.printStackTrace();
        } finally {
            close( connection, stmt, resultSet );
            return groups.toArray( new String[ groups.size() ] );
        }
    }

    /**
     * Create and return a datasource resource.
     * <p>
     * @return A {@link Connection} resource.
     * @throws SecurityStorageException If the datasource jndi name doesn't exists into the context,
     *                                  If the datasource is unreachable because a datasource property isn't valid
     */
    private Connection getConection()
            throws SecurityStorageException
    {
        final String jndi = properties.getProperty( PROPERTY.DATASOURCE_JNDI.toString() );
        final String dbUser = properties.getProperty( PROPERTY.DATABASE_USER.toString() );
        final String dbPassword = properties.getProperty( PROPERTY.DATABASE_PASSWORD.toString() );

        Context ctx = null;
        Connection conn = null;
        String msg;
        try {
            ctx = new InitialContext();
            DataSource dataSource = ( DataSource ) ctx.lookup( jndi );
            if ( dbUser != null && !dbUser.trim().isEmpty() && dbPassword != null && !dbPassword.trim().isEmpty() ) {
                conn = dataSource.getConnection( dbUser, dbPassword );
            } else {
                conn = dataSource.getConnection();
            }
        } catch ( NullPointerException | NamingException ex ) {
            msg = log( Level.SEVERE, "securitystorage.getconnection.naming.exception",
                    jndi, SecurityStorage.class.getName() + ".getConection" );
            throw new SecurityStorageException( msg );
        } catch ( SQLException ex ) {
            msg = log( Level.SEVERE, "securitystorage.getconnection.sql.exception",
                    jndi, SecurityStorage.class.getName() + ".getConection" );
            throw new SecurityStorageException( msg );
        }
        return conn;

    }

    /**
     * Closes a set of resources ({@link Connection}, {@link PreparedStatement} and {@link ResultSet}).
     * <p>
     * @param connection A Connection resource.
     *                   May be <code>null</code>.
     * @param stmt       A PreparedStatement resource.
     *                   May be <code>null</code>.
     * @param res        A ResultSet resource.
     *                   May be <code>null</code>.
     */
    private void close( Connection connection, PreparedStatement stmt, ResultSet res )
    {
        String msg;
        try {
            if ( res != null && !res.isClosed() ) {
                res.close();
            }

            if ( stmt != null && !stmt.isClosed() ) {
                stmt.close();
            }

            if ( connection != null && !connection.isClosed() ) {
                connection.close();
            }
        } catch ( SQLException ex ) {
            log( Level.SEVERE, "securitystorage.close.sql.exception",
                    JDBCRealmExtended.class.getName() + ".close" );
            ex.printStackTrace();
        }

    }

    /**
     * Closes a set of resources ({@link Connection} and {@link PreparedStatement}).
     * <p>
     * @param connection A Connection resource. May be null.
     * @param stmt       A PreparedStatement resource. May be null.
     */
    private void close( Connection conection, PreparedStatement stmt )
    {
        this.close( conection, stmt, null );
    }

    /**
     * Close a {@link Connection} resource.
     * <p>
     * @param connection A resource Connection. May be null.
     */
    private void close( Connection connnection )
    {
        this.close( connnection, null );
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
        String message = secStorSm.getString( key, messVals );
        if ( Logger.getLogger( SecurityStorage.class.getName() ).isLoggable( level ) ) {
            Logger.getLogger( SecurityStorage.class.getName() ).log( level, message );
        }
        return message;
    }
}
