package at.dallermassl.ap.security.taint.trace;

import org.junit.Assert;
import org.junit.Test;

public class TraceTest {
    
    public String trimMethod(String one) {
        return one.trim();
    }

    public String concatAndTrimMethod(String one, String two) {
        return trimMethod(one) + trimMethod(two);
    }


    @Test
    public void traceTest() {
        String foo = new String(" foo ");
        foo.setTainted(true);
        String bar = concatAndTrimMethod(foo, foo);
        Assert.assertTrue(bar.isTainted());
    }

}
