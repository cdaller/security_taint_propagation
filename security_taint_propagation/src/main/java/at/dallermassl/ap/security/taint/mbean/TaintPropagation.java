/**
 *
 */
package at.dallermassl.ap.security.taint.mbean;

import java.util.Date;

import at.dallermassl.ap.security.taint.Configuration;


/**
 * @author christof.dallermassl
 *
 */
public class TaintPropagation implements TaintPropagationMBean {

    /**
     * {@inheritDoc}
     */
    @Override
    public int getCurrentObjectId() {
        String foo = new String(new Date().toString());
        foo.setTainted(true);
        return foo.getTaintedObjectId();
    }

    @Override
    public boolean isCompositePropagationEnabled() {
        return Configuration.isTaintCompositionEnabled();
    }

    @Override
    public void setCompositePropagationEnabled(boolean enabled) {
        Configuration.setTaintCompositionEnabled(enabled);
    }

    @Override
    public boolean isExceptionOnTaintedSink() {
        return Configuration.isExceptionOnTaintedSink();
    }

    @Override
    public void setExceptionOnTaintedSink(boolean exceptionOnTaintedSink) {
        Configuration.setExceptionOnTaintedSink(exceptionOnTaintedSink);
    }

    @Override
    public boolean isLogOnTaintedSink() {
        return Configuration.isLogOnTaintedSink();
    }

    @Override
    public void setLogOnTaintedSink(boolean logOnTaintedSink) {
        Configuration.setLogOnTaintedSink(logOnTaintedSink);
    }

}
