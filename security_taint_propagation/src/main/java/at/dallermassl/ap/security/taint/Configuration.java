package at.dallermassl.ap.security.taint;


public class Configuration {
//    public static boolean TAINTED_COMPOSITION_TRACE_ENABLED = true;

    public static boolean taintedCompositionTraceEnabled = false;
    public static boolean exceptionOnTaintedSink = false;
    public static boolean logOnTaintedSink = true; // default

    public static boolean isTaintCompositionEnabled() {
        return taintedCompositionTraceEnabled;
    }

    public static void setTaintCompositionEnabled(boolean enable) {
        taintedCompositionTraceEnabled = enable;
    }

    public static boolean isExceptionOnTaintedSink() {
        return exceptionOnTaintedSink;
    }

    public static void setExceptionOnTaintedSink(boolean exceptionOnTaintedSink) {
        Configuration.exceptionOnTaintedSink = exceptionOnTaintedSink;
    }

    public static boolean isLogOnTaintedSink() {
        return logOnTaintedSink;
    }

    public static void setLogOnTaintedSink(boolean logOnTaintedSink) {
        Configuration.logOnTaintedSink = logOnTaintedSink;
    }

}
