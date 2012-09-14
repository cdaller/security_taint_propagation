/**
 * 
 */
package at.dallermassl.ap.security.taint.http.sink;

import javax.servlet.jsp.JspWriter;

import at.dallermassl.ap.security.taint.sink.AbstractTaintedSinkAspect;

/**
 * @author cdaller
 *
 */
public aspect JspWriterAspect extends AbstractTaintedSinkAspect {

    /** Aspect for {@link JspWriter#print(String)} */
    before(String value): call(public void JspWriter.print(String)) && args(value) {
        if (value.isTainted()) {
            handleTaintedSink(thisJoinPoint, value);
        }
    }
    
    /** Aspect for {@link JspWriter#println(String)} */
    before(String value): call(public void JspWriter.println(String)) && args(value) {
        if (value.isTainted()) {
            handleTaintedSink(thisJoinPoint, value);
        }
    }

}
