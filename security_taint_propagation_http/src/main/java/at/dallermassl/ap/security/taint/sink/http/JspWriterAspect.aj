/**
 * 
 */
package at.dallermassl.ap.security.taint.sink.http;

import javax.servlet.jsp.JspWriter;

import at.dallermassl.ap.security.taint.sink.AbstractTaintedSinkAspect;

/**
 * @author cdaller
 *
 */
public aspect JspWriterAspect extends AbstractTaintedSinkAspect {
    
    public JspWriterAspect() {
        super("XSS");
    }

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
