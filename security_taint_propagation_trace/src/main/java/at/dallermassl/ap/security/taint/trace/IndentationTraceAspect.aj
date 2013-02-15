package at.dallermassl.ap.security.taint.trace;

import org.aspectj.lang.JoinPoint;

public aspect IndentationTraceAspect extends IndentedLogging { 
    declare precedence: TraceAspect, *;

    protected pointcut loggingOperations():
      (execution(* at.dallermassl..*(..)) || execution(*.new(..)))
       && !within(IndentedLogging+);

    protected void beforeLog(String indent, JoinPoint joinPoint) {
       System.out.println(indent + "Entering ["
            + joinPoint.getSignature().getDeclaringTypeName() + "."
            + joinPoint.getSignature().getName() + "]");
    }

    protected void afterLog(String indent, JoinPoint joinPoint) {
        System.out.println(indent + "Exiting ["
            + joinPoint.getSignature().getDeclaringTypeName() + "."
            + joinPoint.getSignature().getName() + "]");
    }    

}
