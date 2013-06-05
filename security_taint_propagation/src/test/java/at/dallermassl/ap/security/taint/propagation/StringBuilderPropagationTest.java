/**
 *
 */
package at.dallermassl.ap.security.taint.propagation;

import java.util.ArrayList;
import java.util.List;

import org.junit.Assert;
import org.junit.Test;

import at.dallermassl.ap.security.taint.extension.TaintedObject;
import at.dallermassl.ap.security.taint.source.TaintedSourceInfo;

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
        // operation to test
        builder.replace(0, 2, foo);
        Assert.assertFalse("replace StringBuilder propagates untainted", builder.isTainted());

        foo.setTainted(true);

        // operation to test
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

    @Test
    public void testSubsequence() {
        StringBuilder foo = new StringBuilder("foobar");
        foo.setTainted(true);
        CharSequence seq = foo.subSequence(0,  3);
        if (seq instanceof TaintedObject) {
          Assert.assertTrue("subSequence propagates tainted", ((TaintedObject) seq).isTainted());
        }

        foo.setTainted(false);

        // operation to test
        seq = foo.subSequence(0,  3);

        if (seq instanceof TaintedObject) {
          Assert.assertFalse("subSequence propagates tainted", ((TaintedObject) seq).isTainted());
        }
    }


    @Test
    public void testSourceIdPropagation1() {
        StringBuilder foo = new StringBuilder("foo");
        String bar = "bar";
        int sourceId1 = TaintedSourceInfo.addSourceInfo("Test1");
        int sourceId2 = TaintedSourceInfo.addSourceInfo("Test2");

        foo.setTainted(true);
        bar.setTainted(true);
        foo.addTaintedSourceId(sourceId1);
        bar.addTaintedSourceId(sourceId2);

        // operation to test
        StringBuilder baz = foo.append(bar);

        int[] sourceIds = baz.getTaintedSourceIds();
        Assert.assertNotNull("source ids must be not null", sourceIds);

        List<Integer> idList = new ArrayList<Integer>();
        for (int id : sourceIds) {
            idList.add(id);
        }
        Assert.assertTrue("source ids must be merged", idList.contains(sourceId1));
        Assert.assertTrue("source ids must be merged", idList.contains(sourceId2));
    }

    @Test
    public void testSourceIdPropagationStringBuilderStringBufferTrueTrue() {
        StringBuilder foo = new StringBuilder("foo");
        StringBuffer bar = new StringBuffer("bar");
        int sourceId1 = TaintedSourceInfo.addSourceInfo("Test1");
        int sourceId2 = TaintedSourceInfo.addSourceInfo("Test2");

        foo.setTainted(true);
        bar.setTainted(true);
        foo.addTaintedSourceId(sourceId1);
        bar.addTaintedSourceId(sourceId2);

        // operation to test
        StringBuilder baz = foo.append(bar);

        int[] sourceIds = baz.getTaintedSourceIds();
        Assert.assertNotNull("source ids must be not null", sourceIds);

        List<Integer> idList = new ArrayList<Integer>();
        for (int id : sourceIds) {
            idList.add(id);
        }
        Assert.assertTrue("source ids must be merged", idList.contains(sourceId1));
        Assert.assertTrue("source ids must be merged", idList.contains(sourceId2));
    }

    @Test
    public void testSourceIdPropagation2() {
        StringBuilder foo = new StringBuilder("foo");
        String bar = "bar";
        int sourceId2 = TaintedSourceInfo.addSourceInfo("Test2");

        foo.setTainted(false);
        bar.setTainted(true);
        bar.addTaintedSourceId(sourceId2);

        // operation to test
        StringBuilder baz = foo.append(bar);

        int[] sourceIds = baz.getTaintedSourceIds();
        Assert.assertNotNull("source ids must be not null", sourceIds);

        List<Integer> idList = new ArrayList<Integer>();
        for (int id : sourceIds) {
            idList.add(id);
        }
        Assert.assertTrue("source ids must be merged", idList.contains(sourceId2));
    }


    @Test
    public void testSourceIdPropagation3() {
        StringBuilder foo = new StringBuilder("foo");
        String bar = "bar";
        int sourceId1 = TaintedSourceInfo.addSourceInfo("Test1");

        foo.setTainted(true);
        bar.setTainted(false);
        foo.addTaintedSourceId(sourceId1);

        // operation to test
        StringBuilder baz = foo.append(bar);

        int[] sourceIds = baz.getTaintedSourceIds();
        Assert.assertNotNull("source ids must be not null", sourceIds);

        List<Integer> idList = new ArrayList<Integer>();
        for (int id : sourceIds) {
            idList.add(id);
        }
        Assert.assertTrue("source ids must be merged", idList.contains(sourceId1));
    }
}
