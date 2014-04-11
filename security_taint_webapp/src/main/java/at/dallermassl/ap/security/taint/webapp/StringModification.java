package at.dallermassl.ap.security.taint.webapp;

import java.util.Date;

/**
 * Demo class to see if taint propgation survives any string manipulation operations.
 * 
 * @author christof.dallermassl
 */
public class StringModification { 
    public static String appendDate(String value) {
        StringBuilder builder = new StringBuilder(value);
        builder.append(new Date());
        return builder.toString();
    }

}
