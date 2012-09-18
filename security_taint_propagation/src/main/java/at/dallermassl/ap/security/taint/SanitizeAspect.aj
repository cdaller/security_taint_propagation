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
                    call(String *.encodeFor*(String)) // esapi Encoder methods
                    ) {
        if (returnObject != null) {
            returnObject.setTainted(false);
            returnObject.clearTaintedSourceIds();
        }
    }

}
