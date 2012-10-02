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

    /** Aspect for {@link JspWriter#print*(String)} */
    before(String value): args(value) && (
                    call(public void JspWriter.print(String)) || 
                    call(public void JspWriter.println(String)) 
                    ){
        if (value != null && value.isTainted()) {
            handleTaintedSink(thisJoinPoint, value);
        }
    }
}
