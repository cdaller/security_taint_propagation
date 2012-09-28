/**
 * 
 */
package at.dallermassl.ap.security.taint.extension;

import java.util.Arrays;

import org.junit.Assert;
import org.junit.Test;

/**
 * @author cdaller
 *
 */
public class TaintedObjectTest {
    
    @Test
    public void testTainted() {
        String foo = "foo";
        foo.setTainted(true);
        Assert.assertTrue(foo.isTainted());
        foo.setTainted(false);
        Assert.assertFalse(foo.isTainted());
    }

    @Test
    public void testSourceIdBits() {
        String foo = "foo";
        foo.setTainted(true);
        foo.addTaintedSourceId(0);
        foo.addTaintedSourceId(5);
        foo.addTaintedSourceId(8);
        foo.addTaintedSourceId(30);
        int sourceIds = foo.getTaintedSourceIdBits();        
        
        Assert.assertEquals("Source id bit fields do not match", (1 << 0 | 1 << 5 | 1 << 8 | 1 << 30), sourceIds);
        
        try {
            foo.addTaintedSourceId(32);
            Assert.fail("Must not accept ids > 30");
        } catch (IllegalArgumentException e) {
            // ok
        }
        
        int[] ids = foo.getTaintedSourceIds();
        Assert.assertTrue(Arrays.binarySearch(ids, 0) >= 0);
        Assert.assertTrue(Arrays.binarySearch(ids, 5) >= 0);
        Assert.assertTrue(Arrays.binarySearch(ids, 8) >= 0);
        Assert.assertTrue(Arrays.binarySearch(ids, 30) >= 0);
        Assert.assertTrue(Arrays.binarySearch(ids, 2) < 0);
        Assert.assertEquals(4, ids.length);
    }

}
