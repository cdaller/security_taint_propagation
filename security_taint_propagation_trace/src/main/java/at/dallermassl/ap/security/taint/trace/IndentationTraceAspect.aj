package at.dallermassl.ap.security.taint.trace;

import org.aspectj.lang.JoinPoint;

import at.dallermassl.ap.security.taint.extension.TaintedObject;

public aspect IndentationTraceAspect extends AbstractIndentedLoggingAspect { 
    declare precedence: IndentationTraceAspect, *;

    protected pointcut loggingOperations():
      (execution(* at.dallermassl..*(..)) || execution(*.new(..)))
       && !within(AbstractIndentedLoggingAspect+);
    
    private String getIndentationSpaces(int level) {
        StringBuffer sb = new StringBuffer();
        for (int i = 0, spaces = indentationlevel * 2; i < spaces; i++) {
            sb.append(" ");
        }
        return sb.toString();
    }

    protected void beforeLog(int level, JoinPoint joinPoint) {
      final Object[] args = joinPoint.getArgs();
      StringBuilder argString = new StringBuilder();
      boolean taintedAnyArg = false;
      for(int index = 0; index < args.length; index++){
          boolean taintedArg = false;
          final Object argument = args[index];
          if (argument instanceof TaintedObject) {
              if (((TaintedObject) argument).isTainted()) {
                taintedAnyArg = true;
                taintedArg = true;
              }
          }
          argString.append("arg").append(index).append("='").append(argument.toString()).append("'");
          if (taintedArg) {
              argString.append("+");
          }
          argString.append(",");
      }
      StringBuilder output = new StringBuilder();
      output.append(getIndentationSpaces(level));
      output.append("Entering [");
      output.append(joinPoint.getSignature().getDeclaringTypeName());
      output.append(".").append(joinPoint.getSignature().getName());
      if (argString.length() > 0) {
          output.append("args=[").append(argString).append("]");          
      }
      if (taintedAnyArg) {
          System.out.println(output);
      }
    }

    protected void afterLog(int level, JoinPoint joinPoint, Object result) {
        System.out.println(getIndentationSpaces(level) + "Exiting ["
            + joinPoint.getSignature().getDeclaringTypeName() + "."
            + joinPoint.getSignature().getName() + ", result='" + result + "']");
    }    

}
