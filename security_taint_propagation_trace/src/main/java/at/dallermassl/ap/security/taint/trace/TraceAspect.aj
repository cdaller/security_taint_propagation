/**
 *
 */
package at.dallermassl.ap.security.taint.trace;


import org.aspectj.lang.JoinPoint.StaticPart;
import org.aspectj.lang.Signature;

import at.dallermassl.ap.security.taint.extension.TaintedObject;

/**
 * This aspect removes the tainted flag. Use it on cleanup methods like encoding for html output
 * or similar.
 *
 * @author cdaller
 */
public aspect TraceAspect {
    
    pointcut traceMethods() : (execution(* *(..)) && !cflow(within(TraceAspect)));
    
    public void logTrace(StaticPart joinPoint, Object argument, int index) {
        Signature sig = joinPoint.getSignature();
        int line = joinPoint.getSourceLocation().getLine();
//        String sourceName = thisJoinPointStaticPart.getSourceLocation().getWithinType().getCanonicalName();
        String locator = sig + ":" + line;
        System.err.println("Tainted object passed at " + locator + ": arg#" + index + ": '" + argument + "'");        
    }
    
    before() : execution (* *.*(..)) {
        final Object[] args = thisJoinPoint.getArgs();
        for(int index = 0; index < args.length; index++){
            final Object argument = args[index];
            if (argument instanceof TaintedObject) {
                if (((TaintedObject) argument).isTainted()) {
                    //logTrace(thisJoinPointStaticPart, arg, i);
                    Signature sig = thisJoinPointStaticPart.getSignature();
                    int line = thisJoinPointStaticPart.getSourceLocation().getLine();
//                    String sourceName = thisJoinPointStaticPart.getSourceLocation().getWithinType().getCanonicalName();
                    String locator = sig + ":" + line;
                    System.err.println("Tainted object passed at " + locator + ": arg#" + index + ": '" + argument + "'");        
                }
            }
        }
    }
    
}
