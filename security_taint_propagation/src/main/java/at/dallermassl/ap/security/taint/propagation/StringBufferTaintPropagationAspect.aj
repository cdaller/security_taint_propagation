package at.dallermassl.ap.security.taint.propagation;

import at.dallermassl.ap.security.taint.extension.TaintedObject;

/**
 * @author cdaller
 *
 */
public privileged aspect StringBufferTaintPropagationAspect {

    /** Aspect for constructor {@link StringBuffer(CharSequence)} */    
    after(CharSequence value) returning (StringBuffer returnObject): call(StringBuffer.new(CharSequence)) && args(value) {
        if (value != null && value instanceof TaintedObject && ((TaintedObject)value).isTainted()) {
            returnObject.setTainted(true);
            returnObject.addTaintedSourceIdBits(((TaintedObject) value).getTaintedSourceIdBits());
        }            
    }
    
    /** Aspect for constructor {@link StringBuffer(String)} */    
    after(String value) returning (StringBuffer returnObject): call(StringBuffer.new(String)) && args(value) {
        if (value != null && value.isTainted()) {
            returnObject.setTainted(value.isTainted());
            returnObject.addTaintedSourceIdBits(value.getTaintedSourceIdBits());
        }
    }
    
    /** Aspect for {@link StringBuffer#append(String)} */
    after(String value, StringBuffer targetObject) returning (StringBuffer returnObject): 
        call(public StringBuffer StringBuffer.append(String)) && args(value) && target(targetObject) {
        if (value != null && value.isTainted()) {
            returnObject.setTainted(true);
            returnObject.addTaintedSourceIdBits(value.getTaintedSourceIdBits());
        }
        if (targetObject.isTainted()) {
            returnObject.setTainted(true);
            returnObject.addTaintedSourceIdBits(targetObject.getTaintedSourceIdBits());
        }
    }

    /** Aspect for {@link StringBuffer#append(StringBuffer)} */
    after(StringBuffer value, StringBuffer targetObject) returning (StringBuffer returnObject): 
        call(public StringBuffer StringBuffer.append(StringBuffer)) && args(value) && target(targetObject) {
        if (value != null && value.isTainted()) {
            returnObject.setTainted(true);
            returnObject.addTaintedSourceIdBits(value.getTaintedSourceIdBits());
        }
        if (targetObject.isTainted()) {
            returnObject.setTainted(true);
            returnObject.addTaintedSourceIdBits(targetObject.getTaintedSourceIdBits());
        }
    }

    /** Aspect for {@link StringBuffer#insert(int, String)} */
    after(int index, String value, StringBuffer targetObject) returning (StringBuffer returnObject): 
        call(public StringBuffer StringBuffer.insert(int, String)) && args(index, value) && target(targetObject) {
        if (value != null && value.isTainted()) {
            returnObject.setTainted(true);
            returnObject.addTaintedSourceIdBits(value.getTaintedSourceIdBits());
        }
        if (targetObject.isTainted()) {
            returnObject.setTainted(true);
            returnObject.addTaintedSourceIdBits(targetObject.getTaintedSourceIdBits());
        }
    }

    /** Aspect for {@link StringBuffer#replace(int, int String)} */
    after(int index, int len, String value, StringBuffer targetObject) returning (StringBuffer returnObject): 
        call(public StringBuffer StringBuffer.replace(int, int, String)) && 
        args(index, len, value) && 
        target(targetObject) {
        if (value != null && value.isTainted()) {
            returnObject.setTainted(true);
            returnObject.addTaintedSourceIdBits(value.getTaintedSourceIdBits());
        }
        if (targetObject.isTainted()) {
            returnObject.setTainted(true);
            returnObject.addTaintedSourceIdBits(targetObject.getTaintedSourceIdBits());
        }
    }
    
    /** Aspect for {@link String#toString()} */
    after(StringBuffer targetObject) returning (String returnObject): call(public String StringBuffer.toString()) && target(targetObject) {
        returnObject.setTainted(targetObject.isTainted());
        returnObject.addTaintedSourceIdBits(targetObject.getTaintedSourceIdBits());
    }

}
