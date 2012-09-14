/**
 * 
 */
package at.dallermassl.ap.security.taint.propagation;

import org.junit.Assert;
import org.junit.Test;

/**
 * @author cdaller
 *
 */
public class StringBuilderPropagationTest {


    @Test
    public void testConstructor() {
        String foo = "foo";
        foo.setTainted(false);
        StringBuilder builder = new StringBuilder(foo);
        Assert.assertFalse("constructor StringBuilder propagates untainted", builder.isTainted());

        foo.setTainted(true);        
        builder = new StringBuilder(foo);
        Assert.assertTrue("constructor StringBuilder propagates tainted", builder.isTainted());
        
        StringBuilder initBuilder = new StringBuilder("bar");
        initBuilder.setTainted(false);
        builder = new StringBuilder(initBuilder);
        Assert.assertFalse("constructor StringBuilder propagates untainted", builder.isTainted());
        initBuilder.setTainted(true);
        builder = new StringBuilder(initBuilder);
        Assert.assertTrue("constructor StringBuilder propagates tainted", builder.isTainted());

        StringBuffer initBuffer = new StringBuffer("bar");
        initBuffer.setTainted(false);
        builder = new StringBuilder(initBuffer);
        Assert.assertFalse("constructor StringBuilder propagates untainted", builder.isTainted());
        initBuffer.setTainted(true);
        builder = new StringBuilder(initBuffer);
        Assert.assertTrue("constructor StringBuilder propagates tainted", builder.isTainted());
    }

    @Test
    public void testAppend() {
        String foo = "foo";
        foo.setTainted(false);
        String bar = "bar";
        bar.setTainted(false);
        StringBuilder builder = new StringBuilder(bar).append(foo);
        Assert.assertFalse("append StringBuilder propagates untainted", builder.isTainted());

        foo.setTainted(true);        
        builder = new StringBuilder("bar").append(foo);
        Assert.assertTrue("append StringBuilder propagates tainted", builder.isTainted());

        builder = new StringBuilder("foo");
        StringBuilder builder2 = new StringBuilder("bar");
        builder.setTainted(false);
        builder2.setTainted(false);
        Assert.assertFalse("append StringBuilder propagates untainted", builder.append(builder2).isTainted());

        builder.setTainted(true);
        builder2.setTainted(false);
        Assert.assertTrue("append StringBuilder propagates tainted", builder.append(builder2).isTainted());

        builder.setTainted(false);
        builder2.setTainted(true);
        Assert.assertTrue("append StringBuilder propagates tainted", builder.append(builder2).isTainted());

    
        builder = new StringBuilder("foo");
        StringBuffer buffer = new StringBuffer("bar");
        builder.setTainted(false);
        buffer.setTainted(false);
        Assert.assertFalse("append StringBuffer propagates untainted", builder.append(buffer).isTainted());

        builder.setTainted(true);
        buffer.setTainted(false);
        Assert.assertTrue("append StringBuffer propagates tainted", builder.append(buffer).isTainted());

        builder.setTainted(false);
        buffer.setTainted(true);
        Assert.assertTrue("append StringBuffer propagates tainted", builder.append(buffer).isTainted());
        
        builder.setTainted(false);
        Assert.assertFalse("append StringBuffer null propagates tainted", builder.append((String) null).isTainted());
        builder.setTainted(true);
        Assert.assertTrue("append StringBuffer null propagates tainted", builder.append((String) null).isTainted());

    }

    @Test
    public void testInsert() {
        StringBuilder builder = new StringBuilder("bar");
        String foo = "foo";
        builder.setTainted(false);
        foo.setTainted(false);
        builder.insert(0, foo);
        Assert.assertFalse("insert StringBuilder propagates untainted", builder.isTainted());

        foo.setTainted(true);
        builder.insert(0, foo);
        Assert.assertTrue("insert StringBuilder propagates tainted", builder.isTainted());
        
        builder.setTainted(false);
        builder.insert(0, (String) null);
        Assert.assertFalse("insert StringBuilder propagates tainted", builder.isTainted());

        builder.setTainted(true);
        builder.insert(0, (String) null);
        Assert.assertTrue("insert StringBuilder propagates tainted", builder.isTainted());
    }

    @Test
    public void testReplace() {
        StringBuilder builder = new StringBuilder("bar");
        String foo = "foo";
        builder.setTainted(false);
        foo.setTainted(false);
        builder.replace(0, 2, foo);
        Assert.assertFalse("replace StringBuilder propagates untainted", builder.isTainted());

        foo.setTainted(true);
        builder.replace(0, 2, foo);
        Assert.assertTrue("replace StringBuilder propagates tainted", builder.isTainted());
    }

    @Test 
    public void testToString() {
        StringBuilder foo = new StringBuilder("foo");
        foo.setTainted(false);
        foo.setTainted(false);
        Assert.assertFalse("toString of untainted propagates taintedness", foo.toString().isTainted());
        foo.setTainted(true);
        Assert.assertTrue("toString of tainted propagates taintedness", foo.toString().isTainted());
    }
}
