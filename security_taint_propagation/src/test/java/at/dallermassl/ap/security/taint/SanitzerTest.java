/**
 * 
 */
package at.dallermassl.ap.security.taint;

import junit.framework.Assert;

import org.junit.Test;

/**
 * @author cdaller
 *
 */
public class SanitzerTest {
    
    @Test
    public void testSanitizer() {
        Sanitizer sanitizer = new Sanitizer();
        String foo = "foo_bar baz";
        foo.setTainted(false);        
        Assert.assertFalse("sanitize untainted", sanitizer.sanitize(foo).isTainted());
        
        foo.setTainted(true);        
        Assert.assertFalse("sanitize untainted", sanitizer.sanitize(foo).isTainted());
        
        // check if original changed its state: (if sanitizer does nothing (no replacement took place))
        // this will not work!
        Assert.assertTrue("original after sanitation", foo.isTainted());
    }

}
