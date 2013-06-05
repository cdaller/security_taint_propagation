package at.dallermassl.ap.security.taint.util;

import java.io.PrintWriter;
import java.io.StringWriter;

public final class TaintUtils {

    private TaintUtils() {
    }

    public static String[] getStackTraceLines() {
        String trace = getStackTrace();
        String[] traces = trace.split("\n");
        for (int index = 0; index < traces.length; index++) {
            traces[index] = traces[index].trim();
        }
        return traces;
    }

    public static String getStackTrace() {
        StringWriter stringWriter = new StringWriter();
        PrintWriter printWriter = new PrintWriter(stringWriter);
        Throwable throwable = new Throwable();
        throwable.printStackTrace(printWriter);
        return stringWriter.toString();
    }

}
