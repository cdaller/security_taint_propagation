package at.dallermassl.ap.security.taint.propagation;

import java.util.Locale;

import at.dallermassl.ap.security.taint.extension.TaintedObject;

/**
 * @author cdaller
 *
 */
public privileged aspect StringTaintPropagationAspect extends AbstractTaintPropagationAspect {

    /** Aspect for constructor {@link String(String)} or methods using a string as param */
    after(String value) returning (String returnObject):
    args(value) && notInMyAdvice() && (
    call(String.new(String))) {
        propagateTainted(value, returnObject);
    }

    /** Aspect for methods using a string as param */
    after(String value, String targetObject) returning (String returnObject):
    args(value) && target(targetObject) && notInMyAdvice() && (
    call(public String String.concat(String))) {
        propagateTainted(targetObject, returnObject, value);
    }

    /** Aspect for {@link String#toString() or similar} */
    after(String targetObject) returning (String returnObject):
    target(targetObject) && target(java.lang.String) &&
    notInMyAdvice() && (
      call(public String Object.toString()) ||
      call(public String String.trim()) ||
      call(public String String.toLowerCase()) ||
      call(public String String.toLowerCase(Locale)) ||
      call(public String String.toUpperCase()) ||
      call(public String String.toUpperCase(Locale)) ||
      call(public String String.substring(..))
    ) {
        propagateTainted(targetObject, returnObject);
    }

    /** Aspect for {@link CharSequence#subSequence()} */
    after(TaintedObject targetObject) returning (TaintedObject returnObject):
    target(targetObject) && notInMyAdvice() && (
      call(public CharSequence CharSequence.subSequence(..))
    ) {
        propagateTainted(targetObject, returnObject, null);
    }

    /** Aspect for {@link String#toString() or similar} */
    after(String targetObject) returning (String[] returnObjects):
    target(targetObject) && notInMyAdvice() && (
      call(public String[] String.split(String)) ||
      call(public String[] String.split(String, int))
    ) {
        if (targetObject.isTainted()) {
            for (String returnObject : returnObjects) {
                propagateTainted(targetObject, returnObject);
            }
        }
    }

    /** Aspect for methods using a string as param */
    after(String targetObject) returning (String returnObject):
    target(targetObject) && notInMyAdvice() && (
      call(public String String.replace(char, char))
    ) {
        propagateTainted(targetObject, returnObject);
    }

    /** Aspect for methods using a string as param */
    after(CharSequence regexp, CharSequence replacement, String targetObject) returning (String returnObject):
      args(regexp, replacement) && target(targetObject)
      && notInMyAdvice() && (
        call(public String String.replace(CharSequence, CharSequence)) ||
        call(public String String.replaceAll(String, String)) ||
        call(public String String.replaceFirst(String, String))
      ) {
        // <FIXXME date="04.06.2013" author="christof.dallermassl">
        // FIXME: does not work if the regular expression replacement uses back references that return a tainted string!
        // FIXME: the regexp might also be tainted!!
        propagateTainted(targetObject, returnObject, replacement);
        // </FIXXME>
    }

}
