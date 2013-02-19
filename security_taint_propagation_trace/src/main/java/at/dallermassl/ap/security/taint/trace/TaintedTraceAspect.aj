/**
 *
 */
package at.dallermassl.ap.security.taint.trace;


import org.aspectj.lang.JoinPoint;

import at.dallermassl.ap.security.taint.extension.TaintedObject;

/**
 * Trace Aspect for tainted variables.
 * 
 * http://www.jayway.com/2006/12/15/indented-tracing-using-aspectj/
 *
 * @author cdaller
 */
public aspect TaintedTraceAspect { 
    //declare precedence: TaintedTraceAspect, *;

    final static boolean enabled = true;

    final static TaintTracer taintTracer = TaintTracer.getInstance();

    protected pointcut taintTrace():
      (execution(* at.dallermassl..*(..)) || execution(*.new(..)))
       && !within(TaintedTraceAspect) && !within(TraceInfo) && !within(TaintTracer) && if(enabled);
    
    /**
     * The aspect itself wrapping around all methods.
     * @return the object returned by the instrumented method.
     */
    Object around(): taintTrace() {
        beforeTrace(thisJoinPoint);
        Object result = null;
        try {
            result = proceed();
        } finally {
            afterTrace(thisJoinPoint, result);
        }
        return result;
    }
    
    protected void beforeTrace(JoinPoint joinPoint) {
      final Object[] args = joinPoint.getArgs();
      for(int index = 0; index < args.length; index++){
          final Object argument = args[index];
          if (argument instanceof TaintedObject && ((TaintedObject) argument).isTainted()) {
              taintTracer.addEnter((TaintedObject) argument, joinPoint);
          }
       }
    }
    
    protected void afterTrace(JoinPoint joinPoint, Object result) {
//        System.out.println("exit " + joinPoint + ":" + result);
        if (result != null && result instanceof TaintedObject && ((TaintedObject) result).isTainted()) {
            taintTracer.addExit((TaintedObject) result, joinPoint);
        }        
    }
}
