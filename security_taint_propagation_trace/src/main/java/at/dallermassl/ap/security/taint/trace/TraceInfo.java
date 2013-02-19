package at.dallermassl.ap.security.taint.trace;

import java.util.ArrayList;
import java.util.List;

import org.aspectj.lang.JoinPoint;

import at.dallermassl.ap.security.taint.extension.TaintedObject;

public class TraceInfo {
    
    private List<String> traces;
    
    public TraceInfo() {
        traces = new ArrayList<String>();
    }
    
    public void addEnter(JoinPoint joinPoint) {
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
            argString.append("arg");
            argString.append(index);
            argString.append("='");
            argString.append(argument.toString());
            argString.append("'");
            if (taintedArg) {
                argString.append("+");
            }
            argString.append(",");
        }
        StringBuilder output = new StringBuilder();
        output.append("Entering [");
        output.append(joinPoint.getSignature().getDeclaringTypeName());
        output.append(".").append(joinPoint.getSignature().getName());
        if (argString.length() > 0) {
            output.append("args=[").append(argString).append("]");          
        }
        traces.add(output.toString());
    }
    
    public void addExit(JoinPoint joinPoint, Object result) {
        StringBuilder output = new StringBuilder();
        output.append("Exiting [");
        output.append(joinPoint.getSignature().getDeclaringTypeName());
        output.append(".").append(joinPoint.getSignature().getName());
        if (result != null) {
            output.append("ret=[").append(result).append("]");          
        }
        traces.add(output.toString());        
    }
    
    public List<String> getTraces() {
        return traces;
    }

}
