/**
 * 
 */
package at.dallermassl.ap.security.taint;

/**
 * This aspect removes
 * @author cdaller
 *
 */
public aspect SanitizeAspect {
    
    /** Aspect for sanitation methods */    
    after(String value) returning (String returnObject): args(value) && (
                    call(String *.sanitize(String)) ||  // self defined
                    call(String *.encodeFor*(String)) || // esapi Encoder methods
                    call(String *.encodeHtml*(String)) || // SecurityUtils
                    call(String *.hTMLEncode(String)) || //
                    call(String *.htmlencode(String)) // proprietary StringUtils
                    ) {
        if (returnObject != null) {
            returnObject.setTainted(false);
            returnObject.clearTaintedSourceIds();
        }
    }

}
