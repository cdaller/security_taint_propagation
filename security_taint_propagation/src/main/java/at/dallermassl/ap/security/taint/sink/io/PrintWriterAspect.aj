/**
 * 
 */
package at.dallermassl.ap.security.taint.sink.io;

import java.io.PrintWriter;

import at.dallermassl.ap.security.taint.sink.AbstractTaintedSinkAspect;

/**
 * @author cdaller
 * Sinks: Statement.executeQuery(), JspWriter.print(), new File(), Runtime.exec(), ...
 */
public aspect PrintWriterAspect extends AbstractTaintedSinkAspect {
    
    public PrintWriterAspect() {
        super("XSS");
    }
    
    /** Aspect for {@link PrintWriter#print(String)} */
    before(String value): args(value) && (
                    call(public void PrintWriter.print(String)) ||
                    call(public void PrintWriter.println(String))
                    ){
        if (value != null && value.isTainted()) {
            handleTaintedSink(thisJoinPoint, value);
        }
    }
}
