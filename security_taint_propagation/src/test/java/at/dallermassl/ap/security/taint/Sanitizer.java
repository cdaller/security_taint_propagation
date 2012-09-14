/**
 * 
 */
package at.dallermassl.ap.security.taint;


/**
 * @author cdaller
 *
 */
public class Sanitizer {
    
    public String sanitize(String content) {
        String cleaned = content.replace(" ", "_");       
        return cleaned;
    }
}
