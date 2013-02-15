/**
 *
 */
package at.dallermassl.ap.security.taint;

import at.dallermassl.ap.security.taint.extension.TaintedObject;

/**
 * This aspect removes the tainted flag. Use it on cleanup methods like encoding for html output
 * or similar.
 *
 * @author cdaller
 */
public aspect SanitizeAspect {

    public void clearTainted(TaintedObject taintedObject) {
        if (taintedObject != null) {
            taintedObject.setTainted(false);
            taintedObject.clearTaintedSourceIds();
        }
        //System.out.println("clearTainted called");
    }

    /** Aspect for sanitation methods */
    after(String value) returning (String returnObject): args(value) && (
                    call(String *.sanitize(String)) ||  // self defined
                    call(String *.encode*(String)) || // esapi Encoder methods
                    call(String *.hTMLEncode(String)) || //
                    call(String *.htmlencode(String)) // proprietary StringUtils
                    ) {
        clearTainted(returnObject);
    }

}
