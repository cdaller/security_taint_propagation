package at.dallermassl.ap.security.taint.propagation;

import java.util.Locale;

/**
 * @author cdaller
 *
 */
public privileged aspect StringTaintPropagationAspect {
    // TODO: replace and replaceAll...

    /** Aspect for constructor {@link String(String)} or methods using a string as param */    
    after(String value) returning (String returnObject): args(value) && (
                    call(String.new(String)) ||
                    call(public String String.concat(String))
                    ) {
        if (value != null) {
            returnObject.setTainted(value.isTainted());
            returnObject.addTaintedSourceIds(value.getTaintedSourceIds());
        }
    }
        
    /** Aspect for {@link String#toString() or similar} */
    after(String targetObject) returning (String returnObject): target(targetObject) && (
                    call(public String String.toString()) ||
                    call(public String String.trim()) ||
                    call(public String String.toLowerCase()) ||
                    call(public String String.toLowerCase(Locale)) ||
                    call(public String String.toUpperCase()) ||
                    call(public String String.toUpperCase(Locale))
                    ) {
        if (targetObject != null) {
            returnObject.setTainted(targetObject.isTainted());
            returnObject.addTaintedSourceIds(targetObject.getTaintedSourceIds());
        }
    }

    /** Aspect for {@link String#toString() or similar} */
    after(String targetObject) returning (String[] returnObjects): target(targetObject) && (
                    call(public String[] String.split(String)) ||
                    call(public String[] String.split(String, int))
                    ) {
        for (String returnObject : returnObjects) {
            returnObject.setTainted(targetObject.isTainted());
            returnObject.addTaintedSourceIds(targetObject.getTaintedSourceIds());
        }
    }

}
