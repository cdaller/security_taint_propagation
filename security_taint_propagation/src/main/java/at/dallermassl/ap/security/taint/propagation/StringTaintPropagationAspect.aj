package at.dallermassl.ap.security.taint.propagation;

import java.util.Locale;

import at.dallermassl.ap.security.taint.extension.TaintedObject;

/**
 * @author cdaller
 *
 */
public privileged aspect StringTaintPropagationAspect {

    /** Aspect for constructor {@link String(String)} or methods using a string as param */    
    after(String value) returning (String returnObject): args(value) && (
                    call(String.new(String))
                    ) {
        if (value != null) {
            returnObject.setTainted(value.isTainted());
            returnObject.addTaintedSourceIdBits(value.getTaintedSourceIdBits());
        }
    }

    /** Aspect for methods using a string as param */    
    after(String value, String targetObject) returning (String returnObject): args(value) && target(targetObject) && (
                    call(public String String.concat(String))
                    ) {
        if (value != null) {
            returnObject.setTainted(value.isTainted() || targetObject.isTainted());
            returnObject.addTaintedSourceIdBits(value.getTaintedSourceIdBits());
            returnObject.addTaintedSourceIdBits(targetObject.getTaintedSourceIdBits());
        }
    }

    /** Aspect for {@link String#toString() or similar} */
    after(String targetObject) returning (String returnObject): target(targetObject) && (
                    call(public String String.toString()) ||
                    call(public String String.trim()) ||
                    call(public String String.toLowerCase()) ||
                    call(public String String.toLowerCase(Locale)) ||
                    call(public String String.toUpperCase()) ||
                    call(public String String.toUpperCase(Locale)) ||
                    call(public String String.substring(..))
                    ) {
        if (targetObject != null) {
            returnObject.setTainted(targetObject.isTainted());
            returnObject.addTaintedSourceIdBits(targetObject.getTaintedSourceIdBits());
        }
    }

    /** Aspect for {@link CharSequence#subSequence()} */
    after(TaintedObject targetObject) returning (TaintedObject returnObject): target(targetObject) && (
                    call(public CharSequence CharSequence.subSequence(..))
                    ) {
        if (targetObject != null && returnObject instanceof TaintedObject) {
            returnObject.setTainted(targetObject.isTainted());
            returnObject.addTaintedSourceIdBits(targetObject.getTaintedSourceIdBits());
        }
    }

    /** Aspect for {@link String#toString() or similar} */
    after(String targetObject) returning (String[] returnObjects): target(targetObject) && (
                    call(public String[] String.split(String)) ||
                    call(public String[] String.split(String, int))
                    ) {
        for (String returnObject : returnObjects) {
            returnObject.setTainted(targetObject.isTainted());
            returnObject.addTaintedSourceIdBits(targetObject.getTaintedSourceIdBits());
        }
    }

    /** Aspect for methods using a string as param */    
    after(String targetObject) returning (String returnObject): target(targetObject) && (
                    call(public String String.replace(char, char))
                    ) {
            returnObject.setTainted(targetObject.isTainted());
            returnObject.addTaintedSourceIdBits(targetObject.getTaintedSourceIdBits());
    }

    /** Aspect for methods using a string as param */    
    after(CharSequence regexp, CharSequence replacement, String targetObject) returning (String returnObject): 
      args(regexp, replacement) && target(targetObject) &&
      call(public String String.replace(CharSequence, CharSequence)) {
        if (replacement != null) {
            if (replacement instanceof TaintedObject) {
            returnObject.setTainted(((TaintedObject) replacement).isTainted() || targetObject.isTainted());
            returnObject.addTaintedSourceIdBits(((TaintedObject) replacement).getTaintedSourceIdBits());
            returnObject.addTaintedSourceIdBits(targetObject.getTaintedSourceIdBits());
            }
        }
    }

    /** Aspect for methods using a string as param */    
    after(CharSequence regexp, CharSequence replacement, String targetObject) returning (String returnObject): 
      args(regexp, replacement) && target(targetObject) && (
      call(public String String.replaceAll(String, String)) || 
      call(public String String.replaceFirst(String, String)) 
      ) {
        if (replacement != null) {
            if (replacement instanceof TaintedObject) {
            returnObject.setTainted(((TaintedObject) replacement).isTainted() || targetObject.isTainted());
            returnObject.addTaintedSourceIdBits(((TaintedObject) replacement).getTaintedSourceIdBits());
            returnObject.addTaintedSourceIdBits(targetObject.getTaintedSourceIdBits());
            }
        }
    }
    
}
