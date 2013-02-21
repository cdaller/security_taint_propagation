/**
 * 
 */
package at.dallermassl.ap.security.taint.trace;

import org.apache.commons.lang.text.StrBuilder;
import org.junit.Test;

/**
 * @author cdaller
 *
 */
public class StrBuilderPropagationTest {


    @Test
    public void testConstructor() {
        System.out.println("testconstructor");
        
        StrBuilder builder = new StrBuilder();
        //builder.append("foo");
        
//        Assert.assertFalse("constructor StrBuilder default untainted", builder.isTainted());
//        builder.setTainted(true);
//        Assert.assertTrue("constructor StrBuilder tainted", builder.isTainted());
//        
//        String foo = "foo";
//        foo.setTainted(false);
//        builder = new StrBuilder(foo);
//        Assert.assertFalse("constructor StrBuilder propagates untainted", builder.isTainted());
//
//        foo.setTainted(true);        
//        builder = new StrBuilder(foo);
//        Assert.assertTrue("constructor StrBuilder propagates tainted", builder.isTainted());
        
    }

//    @Test
//    public void testAppend() {
//        String foo = "foo";
//        foo.setTainted(false);
//        String bar = "bar";
//        bar.setTainted(false);
//        StrBuilder builder = new StrBuilder(bar).append(foo);
//        Assert.assertFalse("append StrBuilder propagates untainted", builder.isTainted());
//
//        foo.setTainted(true);        
//        builder = new StrBuilder("bar").append(foo);
//        Assert.assertTrue("append StrBuilder propagates tainted", builder.isTainted());
//
//        builder = new StrBuilder("foo");
//        StrBuilder builder2 = new StrBuilder("bar");
//        builder.setTainted(false);
//        builder2.setTainted(false);
//        Assert.assertFalse("append StrBuilder propagates untainted", builder.append(builder2).isTainted());
//
//        builder.setTainted(true);
//        builder2.setTainted(false);
//        Assert.assertTrue("append StrBuilder propagates tainted", builder.append(builder2).isTainted());
//
//        builder.setTainted(false);
//        builder2.setTainted(true);
//        Assert.assertTrue("append StrBuilder propagates tainted", builder.append(builder2).isTainted());
//
//    
//        builder = new StrBuilder("foo");
//        StringBuffer buffer = new StringBuffer("bar");
//        builder.setTainted(false);
//        buffer.setTainted(false);
//        Assert.assertFalse("append StringBuffer propagates untainted", builder.append(buffer).isTainted());
//
//        builder.setTainted(true);
//        buffer.setTainted(false);
//        Assert.assertTrue("append StringBuffer propagates tainted", builder.append(buffer).isTainted());
//
//        builder.setTainted(false);
//        buffer.setTainted(true);
//        Assert.assertTrue("append StringBuffer propagates tainted", builder.append(buffer).isTainted());
//        
//        builder.setTainted(false);
//        Assert.assertFalse("append StringBuffer null propagates tainted", builder.append((String) null).isTainted());
//        builder.setTainted(true);
//        Assert.assertTrue("append StringBuffer null propagates tainted", builder.append((String) null).isTainted());
//
//    }
//
//    @Test
//    public void testInsert() {
//        StrBuilder builder = new StrBuilder("bar");
//        String foo = "foo";
//        builder.setTainted(false);
//        foo.setTainted(false);
//        builder.insert(0, foo);
//        Assert.assertFalse("insert StrBuilder propagates untainted", builder.isTainted());
//
//        foo.setTainted(true);
//        builder.insert(0, foo);
//        Assert.assertTrue("insert StrBuilder propagates tainted", builder.isTainted());
//        
//        builder.setTainted(false);
//        builder.insert(0, (String) null);
//        Assert.assertFalse("insert StrBuilder propagates tainted", builder.isTainted());
//
//        builder.setTainted(true);
//        builder.insert(0, (String) null);
//        Assert.assertTrue("insert StrBuilder propagates tainted", builder.isTainted());
//    }
//
//    @Test
//    public void testReplace() {
//        StrBuilder builder = new StrBuilder("bar");
//        String foo = "foo";
//        builder.setTainted(false);
//        foo.setTainted(false);
//        builder.replace(0, 2, foo);
//        Assert.assertFalse("replace StrBuilder propagates untainted", builder.isTainted());
//
//        foo.setTainted(true);
//        builder.replace(0, 2, foo);
//        Assert.assertTrue("replace StrBuilder propagates tainted", builder.isTainted());
//    }
//
//    @Test 
//    public void testToString() {
//        StrBuilder foo = new StrBuilder("foo");
//        foo.setTainted(false);
//        foo.setTainted(false);
//        Assert.assertFalse("toString of untainted propagates taintedness", foo.toString().isTainted());
//        foo.setTainted(true);
//        Assert.assertTrue("toString of tainted propagates taintedness", foo.toString().isTainted());
//    }
//    
//    @Test
//    public void testSubsequence() {
//        StrBuilder foo = new StrBuilder("foobar");
//        foo.setTainted(true);
//        CharSequence seq = foo.subSequence(0,  3);
//        if (seq instanceof TaintedObject) {
//          Assert.assertTrue("subSequence propagates tainted", ((TaintedObject) seq).isTainted());
//        }
//
//        foo.setTainted(false);
//        seq = foo.subSequence(0,  3);
//        if (seq instanceof TaintedObject) {
//          Assert.assertFalse("subSequence propagates tainted", ((TaintedObject) seq).isTainted());       
//        }
//    }
//
//    
//    @Test
//    public void testSourceIdPropagation1() {
//        StrBuilder foo = new StrBuilder("foo");
//        String bar = "bar";
//        int sourceId1 = TaintedSourceInfo.addSourceInfo("Test1");
//        int sourceId2 = TaintedSourceInfo.addSourceInfo("Test2");
//
//        foo.setTainted(true);
//        bar.setTainted(true);
//        foo.addTaintedSourceId(sourceId1);
//        bar.addTaintedSourceId(sourceId2);
//        
//        StrBuilder baz = foo.append(bar);
//        int[] sourceIds = baz.getTaintedSourceIds();
//        Assert.assertNotNull("source ids must be not null", sourceIds);
//
//        List<Integer> idList = new ArrayList<Integer>();
//        for (int id : sourceIds) {
//            idList.add(id);
//        }       
//        Assert.assertTrue("source ids must be merged", idList.contains(sourceId1));
//        Assert.assertTrue("source ids must be merged", idList.contains(sourceId2));
//    }
//
//    @Test
//    public void testSourceIdPropagationStringBuilderStringBufferTrueTrue() {
//        StrBuilder foo = new StrBuilder("foo");
//        StringBuffer bar = new StringBuffer("bar");
//        int sourceId1 = TaintedSourceInfo.addSourceInfo("Test1");
//        int sourceId2 = TaintedSourceInfo.addSourceInfo("Test2");
//
//        foo.setTainted(true);
//        bar.setTainted(true);
//        foo.addTaintedSourceId(sourceId1);
//        bar.addTaintedSourceId(sourceId2);
//        
//        StrBuilder baz = foo.append(bar);
//        int[] sourceIds = baz.getTaintedSourceIds();
//        Assert.assertNotNull("source ids must be not null", sourceIds);
//
//        List<Integer> idList = new ArrayList<Integer>();
//        for (int id : sourceIds) {
//            idList.add(id);
//        }       
//        Assert.assertTrue("source ids must be merged", idList.contains(sourceId1));
//        Assert.assertTrue("source ids must be merged", idList.contains(sourceId2));
//    }
//
//    @Test
//    public void testSourceIdPropagation2() {
//        StrBuilder foo = new StrBuilder("foo");
//        String bar = "bar";
//        int sourceId2 = TaintedSourceInfo.addSourceInfo("Test2");
//
//        foo.setTainted(false);
//        bar.setTainted(true);
//        bar.addTaintedSourceId(sourceId2);
//        
//        StrBuilder baz = foo.append(bar);
//        int[] sourceIds = baz.getTaintedSourceIds();
//        Assert.assertNotNull("source ids must be not null", sourceIds);
//
//        List<Integer> idList = new ArrayList<Integer>();
//        for (int id : sourceIds) {
//            idList.add(id);
//        }       
//        Assert.assertTrue("source ids must be merged", idList.contains(sourceId2));
//    }
//
//
//    @Test
//    public void testSourceIdPropagation3() {
//        StrBuilder foo = new StrBuilder("foo");
//        String bar = "bar";
//        int sourceId1 = TaintedSourceInfo.addSourceInfo("Test1");
//
//        foo.setTainted(true);
//        bar.setTainted(false);
//        foo.addTaintedSourceId(sourceId1);
//        
//        StrBuilder baz = foo.append(bar);
//        int[] sourceIds = baz.getTaintedSourceIds();
//        Assert.assertNotNull("source ids must be not null", sourceIds);
//
//        List<Integer> idList = new ArrayList<Integer>();
//        for (int id : sourceIds) {
//            idList.add(id);
//        }       
//        Assert.assertTrue("source ids must be merged", idList.contains(sourceId1));
//    }
}
