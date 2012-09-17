package at.dallermassl.ap.security.taint.propagation;

/**
 * @author cdaller
 *
 */
public privileged aspect StringBufferTaintPropagationAspect {

    /** Aspect for constructor {@link StringBuffer(CharSequence)} */    
    after(CharSequence value) returning (StringBuffer returnObject): call(StringBuffer.new(CharSequence)) && args(value) {
        if (value != null) {
            if (value instanceof String) {
                if (((String)value).isTainted()) {
                    returnObject.setTainted(true);
                    returnObject.addTaintedSourceIds(((String) value).getTaintedSourceIds());
                }            
            } else if (value instanceof StringBuilder) {
                if (((StringBuilder)value).isTainted()) {
                    returnObject.setTainted(true);
                    returnObject.addTaintedSourceIds(((StringBuilder) value).getTaintedSourceIds());
                }            
            } else if (value instanceof StringBuffer) {
                if (((StringBuffer)value).isTainted()) {
                    returnObject.setTainted(true);
                    returnObject.addTaintedSourceIds(((StringBuffer) value).getTaintedSourceIds());
                }            
            }
        }
    }
    
    /** Aspect for constructor {@link StringBuffer(String)} */    
    after(String value) returning (StringBuffer returnObject): call(StringBuffer.new(String)) && args(value) {
        if (value != null && value.isTainted()) {
            returnObject.setTainted(value.isTainted());
            returnObject.addTaintedSourceIds(value.getTaintedSourceIds());
        }
    }
    
    /** Aspect for {@link StringBuffer#append(String)} */
    after(String value) returning (StringBuffer returnObject): call(public StringBuffer StringBuffer.append(String)) && args(value) {
        if (value != null && value.isTainted()) {
            returnObject.setTainted(true);
            returnObject.addTaintedSourceIds(value.getTaintedSourceIds());
        }
    }

    /** Aspect for {@link StringBuffer#append(StringBuffer)} */
    after(StringBuffer value) returning (StringBuffer returnObject): call(public StringBuffer StringBuffer.append(StringBuffer)) && args(value) {
        if (value != null && value.isTainted()) {
            returnObject.setTainted(true);
            returnObject.addTaintedSourceIds(value.getTaintedSourceIds());
        }
    }

    /** Aspect for {@link StringBuffer#insert(int, String)} */
    after(int index, String value) returning (StringBuffer returnObject): call(public StringBuffer StringBuffer.insert(int, String)) && args(index, value) {
        if (value != null && value.isTainted()) {
            returnObject.setTainted(true);
            returnObject.addTaintedSourceIds(value.getTaintedSourceIds());
        }
    }

    /** Aspect for {@link StringBuffer#replace(int, int String)} */
    after(int index, int len, String value) returning (StringBuffer returnObject): call(public StringBuffer StringBuffer.replace(int, int, String)) && args(index, len, value) {
        if (value != null && value.isTainted()) {
            returnObject.setTainted(true);
            returnObject.addTaintedSourceIds(value.getTaintedSourceIds());
        }
    }
    
    /** Aspect for {@link String#toString()} */
    after(StringBuffer targetObject) returning (String returnObject): call(public String StringBuffer.toString()) && target(targetObject) {
        returnObject.setTainted(targetObject.isTainted());
        returnObject.addTaintedSourceIds(targetObject.getTaintedSourceIds());
    }

}
