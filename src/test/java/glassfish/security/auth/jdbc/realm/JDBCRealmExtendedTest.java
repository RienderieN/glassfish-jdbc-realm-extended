package glassfish.security.auth.jdbc.realm;

import com.sun.enterprise.security.auth.realm.InvalidOperationException;
import com.sun.enterprise.security.auth.realm.NoSuchUserException;
import glassfish.security.auth.jdbc.util.dao.SecurityStorage;
import glassfish.security.auth.jdbc.util.factory.passwordtypes.IPasswordType;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import org.easymock.EasyMock;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

/**
 *
 * @author RienderieN
 */
public class JDBCRealmExtendedTest
{

    private IPasswordType passwordTypeMocked;
    private SecurityStorage securityStorageMocked;

    @Before
    public void setUp()
            throws Exception
    {
        passwordTypeMocked = EasyMock.createMock( IPasswordType.class );
        securityStorageMocked = EasyMock.createMock( SecurityStorage.class );
    }

    @Test
    public void should_authenticate_user()
    {
        final String[] user = { "ME", "mepasse" };
        final String[] userGroups = { "ME_GROUP", "AN_OTHER_GROUP" };

        EasyMock.reset( securityStorageMocked );
        EasyMock.reset( passwordTypeMocked );
        EasyMock.expect( securityStorageMocked.findPassword( user[0] ) ).andReturn( user[1] + "encrypted" );
        EasyMock.expect( securityStorageMocked.findGroupNames( user[0] ) ).andReturn( userGroups );
        EasyMock.expect( passwordTypeMocked.checkPassword( user[1], user[1] + "encrypted" ) ).andReturn( Boolean.TRUE );
        EasyMock.replay( securityStorageMocked );
        EasyMock.replay( passwordTypeMocked );

        JDBCRealmExtended jdbcre = new JDBCRealmExtended( passwordTypeMocked, securityStorageMocked );
        List<String> groupsFound = Arrays.asList( jdbcre.authenticate( user[0], user[1] ) );
        Assert.assertTrue( "Should authenticate the user ME and return the groups to which it belongs", groupsFound.containsAll( Arrays.asList( userGroups ) ) );
    }

    @Test
    public void should_getGroupNames()
            throws InvalidOperationException, NoSuchUserException
    {
        final String username = "ME";
        final String[] groups = { "ME_GROUP", "THEM_GROUP" };

        EasyMock.reset( securityStorageMocked );
        EasyMock.reset( passwordTypeMocked );
        EasyMock.expect( securityStorageMocked.findGroupNames( username ) ).andReturn( groups );
        EasyMock.replay( securityStorageMocked );

        JDBCRealmExtended jdbcre = new JDBCRealmExtended( passwordTypeMocked, securityStorageMocked );
        ArrayList<String> groupsFound = Collections.list( jdbcre.getGroupNames( username ) );

        Assert.assertTrue( "Should get ME's group names", Arrays.asList( groups ).containsAll( groupsFound ) );

    }
}
