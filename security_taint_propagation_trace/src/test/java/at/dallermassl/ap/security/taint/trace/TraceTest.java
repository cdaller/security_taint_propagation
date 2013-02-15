package at.dallermassl.ap.security.taint.trace;

import org.junit.Assert;
import org.junit.Test;

public class TraceTest {
    
    public String someMethod(String one, String two) {
        return (one + two).trim();
    }


    @Test
    public void traceTest() {
        String foo = new String(" foo ");
        foo.setTainted(true);
        String bar = someMethod(foo, foo);
        Assert.assertTrue(bar.isTainted());
    }

}
