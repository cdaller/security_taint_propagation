package at.dallermassl.ap.security.taint.propagation;


/**
 * @author cdaller
 *
 */
public privileged aspect StringBuilderTaintPropagationAspect extends AbstractTaintPropagationAspect {


    /** Aspect for constructor {@link StringBuilder(CharSequence)} */
    after(CharSequence value) returning (StringBuilder returnObject):
        call(StringBuilder.new(CharSequence)) && args(value)
        && notInMyAdvice() {
        propagateTainted(value, returnObject);
    }

    /** Aspect for constructor {@link StringBuilder(String)} */
    after(String value) returning (StringBuilder returnObject):
        call(StringBuilder.new(String)) && args(value) && notInMyAdvice() {
        propagateTainted(value, returnObject);
    }

    /** Aspect for {@link StringBuilder#append(String)} */
    after(String value, StringBuilder targetObject) returning (StringBuilder returnObject):
        call(public StringBuilder StringBuilder.append(String)) && args(value) && target(targetObject)
        && notInMyAdvice() {
        propagateTainted(targetObject, returnObject, value);
}

    /** Aspect for {@link StringBuilder#append(StringBuffer)} */
    after(StringBuffer value, StringBuilder targetObject) returning (StringBuilder returnObject):
        call(public StringBuilder StringBuilder.append(StringBuffer)) && args(value) && target(targetObject)
        && notInMyAdvice() {
        propagateTainted(targetObject, returnObject, value);
    }

    /** Aspect for {@link StringBuilder#append(CharSequence)} */
    after(CharSequence value, StringBuilder targetObject) returning (StringBuilder returnObject):
        call(public StringBuilder StringBuilder.append(CharSequence)) && args(value) && target(targetObject)
        && notInMyAdvice() {
        propagateTainted(targetObject, returnObject, value);
    }

    /** Aspect for {@link StringBuilder#insert(int, String)} */
    after(int index, String value, StringBuilder targetObject) returning (StringBuilder returnObject):
        call(public StringBuilder StringBuilder.insert(int, String)) && args(index, value) && target(targetObject)
        && notInMyAdvice() {
        propagateTainted(targetObject, returnObject, value);
}

    /** Aspect for {@link StringBuffer#replace(int, int String)} */
    after(int index, int len, String value, StringBuilder targetObject) returning (StringBuilder returnObject):
        call(public StringBuilder StringBuilder.replace(int, int, String))
        && args(index, len, value)
        && target(targetObject)
        && notInMyAdvice() {
        propagateTainted(targetObject, returnObject, value);
    }


    /** Aspect for {@link String#toString()} */
    after(StringBuilder targetObject) returning (String returnObject):
        call(public String Object.toString())
        && target(targetObject)
        && target(StringBuilder)
        && notInMyAdvice(){
        propagateTainted(targetObject, returnObject);
    }

}
