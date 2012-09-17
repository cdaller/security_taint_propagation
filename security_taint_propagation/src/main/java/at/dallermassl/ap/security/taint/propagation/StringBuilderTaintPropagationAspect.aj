package at.dallermassl.ap.security.taint.propagation;

/**
 * @author cdaller
 *
 */
public privileged aspect StringBuilderTaintPropagationAspect {

    
    /** Aspect for constructor {@link StringBuilder(CharSequence)} */    
    after(CharSequence value) returning (StringBuilder returnObject): call(StringBuilder.new(CharSequence)) && args(value) {
        if (value != null) {
            if (value instanceof String) {
                if (((String)value).isTainted()) {
                    returnObject.setTainted(true);
                    returnObject.addTaintedSourceIdBits(((String) value).getTaintedSourceIdBits());
                }            
            } else if (value instanceof StringBuilder) {
                if (((StringBuilder)value).isTainted()) {
                    returnObject.setTainted(true);
                    returnObject.addTaintedSourceIdBits(((StringBuilder) value).getTaintedSourceIdBits());
                }            
            } else if (value instanceof StringBuffer) {
                if (((StringBuffer)value).isTainted()) {
                    returnObject.setTainted(true);
                    returnObject.addTaintedSourceIdBits(((StringBuffer) value).getTaintedSourceIdBits());
                }            
            }
        }
    }

    /** Aspect for constructor {@link StringBuilder(String)} */    
    after(String value) returning (StringBuilder returnObject): call(StringBuilder.new(String)) && args(value) {
        if (value != null && value.isTainted()) {
            returnObject.setTainted(value.isTainted());
            returnObject.addTaintedSourceIdBits(value.getTaintedSourceIdBits());
        }
    }
    
    /** Aspect for {@link StringBuilder#append(String)} */
    after(String value) returning (StringBuilder returnObject): call(public StringBuilder StringBuilder.append(String)) && args(value) {
        if (value != null && value.isTainted()) {
            returnObject.setTainted(true);
            returnObject.addTaintedSourceIdBits(value.getTaintedSourceIdBits());
        }
    }
    
    /** Aspect for {@link StringBuilder#append(StringBuffer)} */
    after(StringBuffer value) returning (StringBuilder returnObject): call(public StringBuilder StringBuilder.append(StringBuffer)) && args(value) {
        if (value != null && value.isTainted()) {
            returnObject.setTainted(true);
            returnObject.addTaintedSourceIdBits(value.getTaintedSourceIdBits());
        }
    }

    /** Aspect for {@link StringBuilder#append(CharSequence)} */
    after(CharSequence value) returning (StringBuilder returnObject): call(public StringBuilder StringBuilder.append(CharSequence)) && args(value) {
        if (value != null) {
            if (value instanceof String) {
                if (((String)value).isTainted()) {
                    returnObject.setTainted(true);
                    returnObject.addTaintedSourceIdBits(((String) value).getTaintedSourceIdBits());
                }            
            } else if (value instanceof StringBuilder) {
                if (((StringBuilder)value).isTainted()) {
                    returnObject.setTainted(true);
                    returnObject.addTaintedSourceIdBits(((StringBuilder) value).getTaintedSourceIdBits());
                }            
            } else if (value instanceof StringBuffer) {
                if (((StringBuffer)value).isTainted()) {
                    returnObject.setTainted(true);
                    returnObject.addTaintedSourceIdBits(((StringBuffer) value).getTaintedSourceIdBits());
                }            
            }
        }
    }

    /** Aspect for {@link StringBuilder#insert(int, String)} */
    after(int index, String value) returning (StringBuilder returnObject): call(public StringBuilder StringBuilder.insert(int, String)) && args(index, value) {
        if (value != null && value.isTainted()) {
            returnObject.setTainted(true);
            returnObject.addTaintedSourceIdBits(value.getTaintedSourceIdBits());
        }
    }

    /** Aspect for {@link StringBuffer#replace(int, int String)} */
    after(int index, int len, String value) returning (StringBuilder returnObject): call(public StringBuilder StringBuilder.replace(int, int, String)) && args(index, len, value) {
        if (value != null && value.isTainted()) {
            returnObject.setTainted(true);
            returnObject.addTaintedSourceIdBits(value.getTaintedSourceIdBits());
        }
    }

    
    /** Aspect for {@link String#toString()} */
    after(StringBuilder targetObject) returning (String returnObject): call(public String StringBuilder.toString()) && target(targetObject) {
        returnObject.setTainted(targetObject.isTainted());
        returnObject.addTaintedSourceIdBits(targetObject.getTaintedSourceIdBits());
    }

}
