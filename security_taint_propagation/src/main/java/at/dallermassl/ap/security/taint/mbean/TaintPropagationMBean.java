package at.dallermassl.ap.security.taint.mbean;


public interface TaintPropagationMBean {

    int getCurrentObjectId();

    void setCompositePropagationEnabled(boolean enabled);

    boolean isCompositePropagationEnabled();

    boolean isExceptionOnTaintedSink();

    void setExceptionOnTaintedSink(boolean exceptionOnTaintedSink);

    boolean isLogOnTaintedSink();

    void setLogOnTaintedSink(boolean logOnTaintedSink);

}
