package at.dallermassl.ap.security.taint.trace;

import org.aspectj.lang.JoinPoint;

import at.dallermassl.ap.security.taint.extension.TaintedObject;

public aspect IndentationTraceAspect extends AbstractIndentedLoggingAspect { 
    //declare precedence: *, IndentationTraceAspect;

    final static boolean enabled = false;

    protected pointcut loggingOperations():
      (execution(* at.dallermassl..*(..)) || execution(*.new(..)))
       && !within(AbstractIndentedLoggingAspect+) && !within(TraceInfo) && !within(TaintTracer) && if(enabled);
    
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
      for(int index = 0; index < args.length; index++){
          boolean taintedArg = false;
          final Object argument = args[index];
          if (argument instanceof TaintedObject) {
              if (((TaintedObject) argument).isTainted()) {
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
      System.out.println(output);
    }

    protected void afterLog(int level, JoinPoint joinPoint, Object result) {
        boolean tainted = result instanceof TaintedObject && ((TaintedObject) result).isTainted();
        StringBuilder builder = new StringBuilder();
        builder.append(getIndentationSpaces(level));
        builder.append("Exiting [");
        builder.append(joinPoint.getSignature().getDeclaringTypeName());
        builder.append(".");
        builder.append(joinPoint.getSignature().getName());
        builder.append(", result='");
        builder.append(result);
        builder.append("'");
        if (tainted) {
            builder.append("+");
        }
        builder.append("]");
        System.out.println(builder);
    }    

}
