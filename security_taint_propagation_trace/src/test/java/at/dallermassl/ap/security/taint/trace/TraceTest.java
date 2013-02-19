package at.dallermassl.ap.security.taint.trace;

import org.aspectj.lang.Aspects;
import org.junit.Assert;
import org.junit.Test;

public class TraceTest {
    static int count = 0;
    
    public String noop(String one) {
        return one;
    }
    
    public String trimMethod(String one) {
        return one.trim();
    }

    public String concatAndTrimMethod(String one, String two) {
        return trimMethod(one) + trimMethod(two);
    }
    
    public TestTainted source() {
        TestTainted taintedSource = new TestTainted();
        taintedSource.setTainted(true);
        return taintedSource;
    }


    @Test
    public void traceTest() {
        System.out.println("tracetest");
        String foo = new String(" foo ");
        String bar = new String(" bar ");
        foo.setTainted(true);
        bar.setTainted(false);
        String baz = concatAndTrimMethod(foo, bar);
        
//        String foo2 = noop(foo);
//        String foo2Trimmed = trimMethod(foo2);
                
        TaintTracer.getInstance().printInfos(foo, System.out);
        
        Assert.assertTrue(baz.isTainted());
    }
    
    @Test
    public void sourceTest() {
        System.out.println("sourcetest");
        for (int i = 0; i < 10; i++) {
            TestTainted foo = source();
            System.out.println(Aspects.aspectOf(PerObjAspect.class, foo).getIndex());
        }
    }

}
