package at.dallermassl.ap.security.taint.webapp;

import java.util.Date;

public class StringModification {

    public static String appendDate(String input) {
        String output = input.concat(" , date=");
        StringBuffer buffer = new StringBuffer(output);
        buffer.append(new Date().toString());
        return buffer.toString();
    }

}
