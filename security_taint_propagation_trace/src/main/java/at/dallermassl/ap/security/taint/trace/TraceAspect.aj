/**
 *
 */
package at.dallermassl.ap.security.taint.trace;


import org.aspectj.lang.JoinPoint.StaticPart;
import org.aspectj.lang.Signature;

import at.dallermassl.ap.security.taint.extension.TaintedObject;

/**
 * Trace Aspect for tainted variables.
 * 
 * http://www.jayway.com/2006/12/15/indented-tracing-using-aspectj/
 *
 * @author cdaller
 */
public aspect TraceAspect {
    
    /**
     * The current number of indentation levels.
     */
    protected int indentationlevel = 0;
    
//    pointcut traceMethods() : (call(* at.dallermassl..*(..)) && !cflow(within(TraceAspect)));
        
//    before() : traceMethods() {
//        final Object[] args = thisJoinPoint.getArgs();
//        for(int index = 0; index < args.length; index++){
//            final Object argument = args[index];
//            if (argument instanceof TaintedObject) {
//                if (((TaintedObject) argument).isTainted()) {
//                    logTrace(thisJoinPointStaticPart, argument, index);
//                }
//            }
//        }
//    }
    
//    pointcut traceCallStack() : (execution(* *.*(..)) && !within(TraceAspect));
//
//    Object around() : traceCallStack() {
//        indentationlevel++;
//        // check input arguments:
//        final Object[] args = thisJoinPoint.getArgs();
//        for(int index = 0; index < args.length; index++){
//            final Object argument = args[index];
//            if (argument instanceof TaintedObject) {
//                if (((TaintedObject) argument).isTainted()) {
//                    logTrace(thisJoinPointStaticPart, argument, index);
//                }
//            }
//        }
//        // execute method
//        Object result;
//        try {
//            result = proceed();
//            // check return value if any:
//            if (result != null && result instanceof TaintedObject) {
//                logTrace(thisJoinPointStaticPart, result, -1);
//            }
//        } finally {
//            indentationlevel--;
//        }        
//        return result;
//    }

    public void logTrace(StaticPart joinPoint, Object argument, int index) {
        Signature sig = joinPoint.getSignature();
        int line = joinPoint.getSourceLocation().getLine();
//        String sourceName = thisJoinPointStaticPart.getSourceLocation().getWithinType().getCanonicalName();
        String locator = sig + ":" + line;
        System.err.println(indentationlevel + " Tainted object passed at " + locator + ": arg#" + index + ": '" + argument + "'");        
    }

}
