package at.dallermassl.ap.security.taint.propagation;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Locale;
import java.util.Set;

import org.junit.Assert;
import org.junit.Test;

import at.dallermassl.ap.security.taint.source.TaintedSourceInfo;



/**
 * @author cdaller
 *
 */
public class StringTaintPropagationTest {
    
    @Test
    public void constructorTest() {
        String foo = new String("fooConstructorTest");
        Assert.assertFalse("default is untainted", foo.isTainted());

        String bar = new String(foo);
        Assert.assertFalse("copy constructor propagates tainted", bar.isTainted());        
        
        foo.setTainted(true);
        bar = new String(foo);
        Assert.assertTrue("copy constructor propagates tainted", bar.isTainted());        
    }
    
    @Test
    public void testSetTainted() {
        String foo = new String("foo");
        foo.setTainted(false);
        Assert.assertFalse("default is untainted", foo.isTainted());
        foo.setTainted(true);
        Assert.assertTrue("set tainted", foo.isTainted());
    }
        
    @Test 
    public void testConcat() {
        String foo = "foo";
        String bar = "bar";
        
        foo.setTainted(false);
        bar.setTainted(false);
        Assert.assertFalse("concat untainted and untainted", foo.concat(bar).isTainted());
        
        bar.setTainted(true);
        Assert.assertTrue("concat untainted and tainted", foo.concat(bar).isTainted());
        
        foo.setTainted(true);
        Assert.assertTrue("concat tainted and tainted", foo.concat(bar).isTainted());
        
        foo.setTainted(true);
        bar.setTainted(false);
        Assert.assertTrue("concat tainted and tainted", foo.concat(bar).isTainted());
        Assert.assertTrue("concat tainted and tainted", foo.concat(null).isTainted());
        
        
    }
    
    @Test
    public void testToString() {
        String foo = "foo";
        foo.setTainted(false);
        Assert.assertFalse("toString of untainted propagates taintedness", foo.toString().isTainted());
        foo.setTainted(true);
        Assert.assertTrue("toString of tainted propagates taintedness", foo.toString().isTainted());
    }
    
    @Test
    public void testPlusOperator() {
        String one = "one";
        String two = "two";
        String result;
        
        one.setTainted(true);
        two.setTainted(false);
        result = one + two;
        Assert.assertTrue("tainted + untainted = tainted", result.isTainted());

        one.setTainted(false);
        two.setTainted(false);
        result = one + two;
        Assert.assertFalse("untainted + untainted = untainted", result.isTainted());

        one.setTainted(true);
        two.setTainted(true);
        result = one + two;
        Assert.assertTrue("tainted + tainted = tainted", result.isTainted());

        one.setTainted(true);
        result = one + 1000;
        Assert.assertTrue("tainted + number = tainted", result.isTainted());
        result = 1000 + one;
        Assert.assertTrue("number  + tainted = tainted", result.isTainted());
        one.setTainted(false);
        result = one + 1000;
        Assert.assertFalse("untainted + number = untainted", result.isTainted());

        one.setTainted(true);
        result = one + true;
        Assert.assertTrue("tainted + boolean = tainted", result.isTainted());
        one.setTainted(false);
        result = one + true;
        Assert.assertFalse("untainted + boolean = untainted", result.isTainted());

        one.setTainted(true);
        result = one + 1.5;
        Assert.assertTrue("tainted + double = tainted", result.isTainted());
        one.setTainted(false);
        result = one + 1.5;
        Assert.assertFalse("untainted + double = untainted", result.isTainted());

        one.setTainted(true);
        result = one + 1.5f;
        Assert.assertTrue("tainted + float = tainted", result.isTainted());
        one.setTainted(false);
        result = one + 1.5f;
        Assert.assertFalse("untainted + float = untainted", result.isTainted());
    }   
    
    @Test
    public void testTrim() {
        String foo = "foo ";
        foo.setTainted(false);
        Assert.assertFalse("trim untainted", foo.trim().isTainted());
        foo.setTainted(true);
        Assert.assertTrue("trim tainted", foo.trim().isTainted());
    }
    
    @Test
    public void testToLowerCase() {
        String foo = "foo ";
        foo.setTainted(false);
        Assert.assertFalse("lowercase untainted", foo.toLowerCase().isTainted());
        Assert.assertFalse("lowercase untainted", foo.toLowerCase(Locale.GERMAN).isTainted());
        foo.setTainted(true);
        Assert.assertTrue("lowercase tainted", foo.toLowerCase().isTainted());
        Assert.assertTrue("lowercase tainted", foo.toLowerCase(Locale.GERMAN).isTainted());        
    }

    @Test
    public void testToUpperCase() {
        String foo = "foo ";
        foo.setTainted(false);
        Assert.assertFalse("uppercase untainted", foo.toUpperCase().isTainted());
        Assert.assertFalse("uppercase untainted", foo.toUpperCase(Locale.GERMAN).isTainted());
        foo.setTainted(true);
        Assert.assertTrue("uppercase tainted", foo.toUpperCase().isTainted());
        Assert.assertTrue("uppercase tainted", foo.toUpperCase(Locale.GERMAN).isTainted());        
    }
    
    @Test
    public void testSplit() {
        String foo = "foo bar baz";
        foo.setTainted(false);
        for (String part : foo.split(" ")) {
            Assert.assertFalse("split untainted", part.isTainted());            
        }
        for (String part : foo.split(" ", 2)) {
            Assert.assertFalse("split untainted", part.isTainted());            
        }
        foo.setTainted(true);
        for (String part : foo.split(" ")) {
            Assert.assertTrue("split tainted", part.isTainted());            
        }
        for (String part : foo.split(" ", 2)) {
            Assert.assertTrue("split tainted", part.isTainted());            
        }
    }
    
   @Test
   public void testSourceIdPropagation() {
       String foo = "foo";
       String bar = "bar";
       foo.setTainted(true);
       bar.setTainted(true);
       int sourceId1 = TaintedSourceInfo.addSourceInfo("Test1");
       int sourceId2 = TaintedSourceInfo.addSourceInfo("Test2");
       foo.addTaintedSourceId(sourceId1);
       bar.addTaintedSourceId(sourceId2);
       
       String baz = foo.concat(bar);
       int[] sourceIds = baz.getTaintedSourceIds();
       Assert.assertNotNull("source ids must be not null", sourceIds);
       Assert.assertTrue("source ids must be merged", Arrays.asList(sourceIds).contains(sourceId1));
       Assert.assertTrue("source ids must be merged", Arrays.asList(sourceIds).contains(sourceId2));
   }

}
