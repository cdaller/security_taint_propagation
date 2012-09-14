/**
 * 
 */
package at.dallermassl.ap.security.taint;

/**
 * @author cdaller
 *
 */
public aspect SanitizeAspect {
    
    /** Aspect for sanitation methods */    
    after(String value) returning (String returnObject): args(value) && (
                    call(String *.sanitize(String))
                    ) {
        if (returnObject != null) {
            returnObject.setTainted(false);
        }
    }

}
