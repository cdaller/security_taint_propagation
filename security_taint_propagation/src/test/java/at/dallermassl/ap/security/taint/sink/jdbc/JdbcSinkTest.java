/**
 * 
 */
package at.dallermassl.ap.security.taint.sink.jdbc;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

import junit.framework.Assert;

import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import at.dallermassl.ap.security.taint.sink.sql.JdbcSinkAspect;

/**
 * @author cdaller
 *
 */
public class JdbcSinkTest {
    private static Connection conn = null;

    @BeforeClass
    public static void initDb() throws Exception {
        //        String dbURL = "jdbc:derby:memory:myDB;create=true;user=me;password=mine";
        String dbURL = "jdbc:derby:memory:myDB;create=true";
        Class.forName("org.apache.derby.jdbc.EmbeddedDriver").newInstance();

        //Get a connection
        conn = DriverManager.getConnection(dbURL);
    }

    @AfterClass
    public static void shutdownDb() throws Exception {
        if (conn != null) {
            conn.close();
            //String shutdownUrl = "jdbc:derby:memory:myDB;drop=true";
        }
    }

    @Before
    public void initTable() throws SQLException {
        // create simple table to be used.
        Statement stmt = conn.createStatement();
        //stmt.executeUpdate("drop table test");
        stmt.executeUpdate("CREATE TABLE test (" +
        		             "id INTEGER NOT NULL GENERATED ALWAYS AS IDENTITY," +
        		             "intvalue INT, " +
        		             "stringvalue VARCHAR(200))");
        stmt.close();
    }
    
    @After
    public void dropTable() throws SQLException {
        Statement stmt = conn.createStatement();
        stmt.executeUpdate("drop table test");
        stmt.close();
    }
 
    @Test
    public void testStatement() throws SQLException {

        boolean blockTainted = JdbcSinkAspect.isBlockTainted();
        JdbcSinkAspect.setBlockTainted(true);

        try {
            String foo = "foo";
            foo.setTainted(true);
            //System.out.println("printing tainted:");
            Statement stmt = conn.createStatement();
            ResultSet rs;
            // test if it works at all:
            stmt.executeUpdate("insert into test (intvalue, stringvalue) values (1, 'foobar')");

            try {                
                // test execute with tainted string:
                stmt.executeUpdate("insert into test (intvalue, stringvalue) values (2, '" + foo + "')");
                Assert.fail("sql with tainted string must throw a SecurityException");
            } catch (SecurityException e) {
                Assert.assertTrue("Security exception was thrown", true);
            }

            try {                
                // test execute with tainted string:
                stmt.executeUpdate("insert into test (intvalue, stringvalue) values (2, '" + foo + "')", 1);
                Assert.fail("sql with tainted string must throw a SecurityException");
            } catch (SecurityException e) {
                Assert.assertTrue("Security exception was thrown", true);
            }
            
            try {                
                // test execute with tainted string:
                stmt.executeUpdate("insert into test (intvalue, stringvalue) values (2, '" + foo + "')", new int[] {1, 2});
                Assert.fail("sql with tainted string must throw a SecurityException");
            } catch (SecurityException e) {
                Assert.assertTrue("Security exception was thrown", true);
            }    

            try {                
                // test execute with tainted string:
                stmt.executeUpdate("insert into test values (intvalue, stringvalue) (2, '" + foo + "')", new String[] {"intvalue"});
                Assert.fail("sql with tainted string must throw a SecurityException");
            } catch (SecurityException e) {
                Assert.assertTrue("Security exception was thrown", true);
            }
            
            stmt.execute("insert into test (intvalue, stringvalue) values (1, 'foobar')");

            try {                
                // test execute with tainted string:
                stmt.execute("insert into test (intvalue, stringvalue) values (2, '" + foo + "')");
                Assert.fail("sql with tainted string must throw a SecurityException");
            } catch (SecurityException e) {
                Assert.assertTrue("Security exception was thrown", true);
            }

            try {                
                // test execute with tainted string:
                stmt.execute("insert into test (intvalue, stringvalue) values (2, '" + foo + "')", 1);
                Assert.fail("sql with tainted string must throw a SecurityException");
            } catch (SecurityException e) {
                Assert.assertTrue("Security exception was thrown", true);
            }
            
            try {                
                // test execute with tainted string:
                stmt.execute("insert into test (intvalue, stringvalue) values (2, '" + foo + "')", new int[] {1, 2});
                Assert.fail("sql with tainted string must throw a SecurityException");
            } catch (SecurityException e) {
                Assert.assertTrue("Security exception was thrown", true);
            }

            try {                
                // test execute with tainted string:
                stmt.execute("insert into test values (intvalue, stringvalue) (2, '" + foo + "')", new String[] {"intvalue"});
                Assert.fail("sql with tainted string must throw a SecurityException");
            } catch (SecurityException e) {
                Assert.assertTrue("Security exception was thrown", true);
            }
            
            rs = stmt.executeQuery("select * from test where stringvalue = 'foobar'");
            rs.close();
            try {                
                // test execute with tainted string:
                rs = stmt.executeQuery("select * from test where stringvalue = '" + foo + "'");
                Assert.fail("sql with tainted string must throw a SecurityException");
            } catch (SecurityException e) {
                Assert.assertTrue("Security exception was thrown", true);
            }
            rs.close();
            
        } finally {
            JdbcSinkAspect.setBlockTainted(blockTainted);
        }

    }
    
    @Test
    public void testPreparedStatement() throws SQLException {

        boolean blockTainted = JdbcSinkAspect.isBlockTainted();
        JdbcSinkAspect.setBlockTainted(true);

        try {
            String foo = "foo";
            foo.setTainted(true);
            PreparedStatement stmt;
            ResultSet rs;
            // test if it works at all:
            stmt = conn.prepareStatement("insert into test (intvalue, stringvalue) values (1, 'foobar')");

            try {                
                // test execute with tainted string:
                stmt = conn.prepareStatement("insert into test (intvalue, stringvalue) values (2, '" + foo + "')");
                Assert.fail("sql with tainted string must throw a SecurityException");
            } catch (SecurityException e) {
                Assert.assertTrue("Security exception was thrown", true);
            }

            try {                
                // test execute with tainted string:
                stmt = conn.prepareStatement("insert into test (intvalue, stringvalue) values (2, '" + foo + "')", 1);
                Assert.fail("sql with tainted string must throw a SecurityException");
            } catch (SecurityException e) {
                Assert.assertTrue("Security exception was thrown", true);
            }
            
            try {                
                // test execute with tainted string:
                stmt = conn.prepareStatement("insert into test (intvalue, stringvalue) values (2, '" + foo + "')", 1, 2);
                Assert.fail("sql with tainted string must throw a SecurityException");
            } catch (SecurityException e) {
                Assert.assertTrue("Security exception was thrown", true);
            }

            try {                
                // test execute with tainted string:
                stmt = conn.prepareStatement("insert into test (intvalue, stringvalue) values (2, '" + foo + "')", 1, 2, 3);
                Assert.fail("sql with tainted string must throw a SecurityException");
            } catch (SecurityException e) {
                Assert.assertTrue("Security exception was thrown", true);
            }

            try {                
                // test execute with tainted string:
                stmt = conn.prepareStatement("insert into test (intvalue, stringvalue) values (2, '" + foo + "')", new int[] {1, 2});
                Assert.fail("sql with tainted string must throw a SecurityException");
            } catch (SecurityException e) {
                Assert.assertTrue("Security exception was thrown", true);
            }    

            try {                
                // test execute with tainted string:
                stmt = conn.prepareStatement("insert into test values (intvalue, stringvalue) (2, '" + foo + "')", new String[] {"intvalue"});
                Assert.fail("sql with tainted string must throw a SecurityException");
            } catch (SecurityException e) {
                Assert.assertTrue("Security exception was thrown", true);
            }                      
        } finally {
            JdbcSinkAspect.setBlockTainted(blockTainted);
        }

    }


}
