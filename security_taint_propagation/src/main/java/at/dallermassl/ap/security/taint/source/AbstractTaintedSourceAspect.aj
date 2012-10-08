/**
 * 
 */
package at.dallermassl.ap.security.taint.source;

import org.aspectj.lang.JoinPoint;

import at.dallermassl.ap.security.taint.extension.TaintedObject;

/**
 * @author cdaller
 */
public abstract aspect AbstractTaintedSourceAspect {
    
    public void postProcessTaintedSource(JoinPoint joinPoint, TaintedObject value) {
        // workaround for Problem of source methods returning an empty string constant
        // which is then marked as tainted everywhere.
        if (value != null && value instanceof String && ((String) value).isEmpty()) {
            value.setTainted(false);
            value.clearTaintedSourceIds();
        }
    }

}
