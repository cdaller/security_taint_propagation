/**
 *
 */
package at.dallermassl.ap.security.taint.propagation;

import org.junit.Assert;
import org.junit.Test;

import at.dallermassl.ap.security.taint.extension.TaintedObject;

/**
 * @author cdaller
 *
 */
public class StringBufferPropagationTest {

    @Test
    public void testConstructor() {
        String foo = "foo";
        foo.setTainted(false);
        StringBuffer builder = new StringBuffer(foo);
        Assert.assertFalse("constructor StringBuffer propagates untainted", builder.isTainted());

        foo.setTainted(true);
        builder = new StringBuffer(foo);
        Assert.assertTrue("constructor StringBuffer propagates tainted", builder.isTainted());

        StringBuilder initBuilder = new StringBuilder("bar");
        initBuilder.setTainted(false);
        builder = new StringBuffer(initBuilder);
        Assert.assertFalse("constructor StringBuffer propagates untainted", builder.isTainted());
        initBuilder.setTainted(true);
        builder = new StringBuffer(initBuilder);
        Assert.assertTrue("constructor StringBuffer propagates tainted", builder.isTainted());

        StringBuffer initBuffer = new StringBuffer("bar");
        initBuffer.setTainted(false);
        builder = new StringBuffer(initBuffer);
        Assert.assertFalse("constructor StringBuffer propagates untainted", builder.isTainted());
        initBuffer.setTainted(true);
        builder = new StringBuffer(initBuffer);
        Assert.assertTrue("constructor StringBuffer propagates tainted", builder.isTainted());

    }

    @Test
    public void testAppend() {
        String foo = "foo";
        foo.setTainted(false);
        StringBuffer builder = new StringBuffer("bar").append(foo);
        Assert.assertFalse("append StringBuffer propagates untainted", builder.isTainted());

        foo.setTainted(true);
        builder = new StringBuffer("bar").append(foo);
        Assert.assertTrue("append StringBuffer propagates tainted", builder.isTainted());

        builder = new StringBuffer("foo");
        StringBuffer builder2 = new StringBuffer("bar");
        builder.setTainted(false);
        builder2.setTainted(false);
        Assert.assertFalse("append StringBuffer propagates untainted", builder.append(builder2).isTainted());

        builder.setTainted(true);
        builder2.setTainted(false);
        Assert.assertTrue("append StringBuffer propagates tainted", builder.append(builder2).isTainted());

        builder.setTainted(false);
        builder2.setTainted(true);
        Assert.assertTrue("append StringBuffer propagates tainted", builder.append(builder2).isTainted());

        builder.setTainted(false);
        Assert.assertFalse("append StringBuffer null propagates tainted", builder.append((String) null).isTainted());
        builder.setTainted(true);
        Assert.assertTrue("append StringBuffer null propagates tainted", builder.append((String) null).isTainted());

        String baz = "foobarbaz";
        baz.setTainted(false);
        Object bazObj = baz;
        builder.setTainted(false);
        Assert.assertFalse("append StringBuffer Object propagates tainted", builder.append(bazObj).isTainted());
        baz.setTainted(true);
        Assert.assertTrue("append StringBuffer Object propagates tainted", builder.append(bazObj).isTainted());
        baz.setTainted(false);
        builder.setTainted(true);
        Assert.assertTrue("append StringBuffer Object propagates tainted", builder.append(bazObj).isTainted());
        baz.setTainted(true);
        builder.setTainted(false);
        Assert.assertTrue("append StringBuffer Object propagates tainted", builder.append(bazObj).isTainted());

    }

    @Test
    public void testAppendObject() {
        StringBuffer builder = new StringBuffer();
        // test special case where the object is not a string, but String.valueOf/toString is used!
        builder.setTainted(false);
        Object obj = new Object() {
            public String toString() {
                String object = "taintedobject";
                object.setTainted(true);
                return object;
            }
        };
        Assert.assertTrue("toString() propagates tainted", obj.toString().isTainted());
        Assert.assertTrue("String.valueOf propagates tainted", String.valueOf(obj).isTainted());
        Assert.assertTrue("appending StringBuffer.append(obj.toString) propagates tainted", builder.append(obj).isTainted());
    }

    @Test
    public void testInsert() {
        StringBuffer builder = new StringBuffer("bar");
        String foo = "foo";
        builder.setTainted(false);
        foo.setTainted(false);
        builder.insert(0, foo);
        Assert.assertFalse("insert StringBuffer propagates untainted", builder.isTainted());

        foo.setTainted(true);
        builder.insert(0, foo);
        Assert.assertTrue("insert StringBuffer propagates tainted", builder.isTainted());

        builder.setTainted(false);
        builder.insert(0, (String) null);
        Assert.assertFalse("insert StringBuffer propagates tainted", builder.isTainted());

        builder.setTainted(true);
        builder.insert(0, (String) null);
        Assert.assertTrue("insert StringBuffer propagates tainted", builder.isTainted());

    }

    @Test
    public void testReplace() {
        StringBuffer builder = new StringBuffer("bar");
        String foo = "foo";
        builder.setTainted(false);
        foo.setTainted(false);
        builder.replace(0, 2, foo);
        Assert.assertFalse("replace StringBuffer propagates untainted", builder.isTainted());

        foo.setTainted(true);
        builder.replace(0, 2, foo);
        Assert.assertTrue("replace StringBuffer propagates tainted", builder.isTainted());
    }

    @Test
    public void testToString() {
        StringBuffer foo = new StringBuffer("foo");
        foo.setTainted(false);
        foo.setTainted(false);
        Assert.assertFalse("toString of untainted propagates taintedness", foo.toString().isTainted());
        foo.setTainted(true);
        Assert.assertTrue("toString of tainted propagates taintedness", foo.toString().isTainted());
    }

    @Test
    public void testSubsequence() {
        StringBuffer foo = new StringBuffer("foobar");
        foo.setTainted(true);
        CharSequence seq = foo.subSequence(0,  3);
        if (seq instanceof TaintedObject) {
          Assert.assertTrue("subSequence propagates tainted", ((TaintedObject) seq).isTainted());
        }

        foo.setTainted(false);
        seq = foo.subSequence(0,  3);
        if (seq instanceof TaintedObject) {
          Assert.assertFalse("subSequence propagates tainted", ((TaintedObject) seq).isTainted());
        }
    }


}
