/**
 * 
 */
package at.dallermassl.ap.security.taint.webapp;

/**
 * @author cdaller
 *
 */
public class Sanitizer {
    public static String sanitize(String value) {
        String secure = value.replace("<", "&lt");
        return new String(secure);
    }

}
