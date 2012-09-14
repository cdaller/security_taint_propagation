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
    
    /** Aspect for {@link PrintWriter#print(String)} */
    before(String value): call(public void PrintWriter.print(String)) && args(value) {
        if (value != null && value.isTainted()) {
            handleTaintedSink(thisJoinPoint, value);
        }
    }

    /** Aspect for {@link PrintWriter#print(String)} */
    before(String value): call(public void PrintWriter.println(String)) && args(value) {
        //System.out.println(thisJoinPoint.toLongString());
        if (value != null && value.isTainted()) {
            handleTaintedSink(thisJoinPoint, value);
        }
    }
}
