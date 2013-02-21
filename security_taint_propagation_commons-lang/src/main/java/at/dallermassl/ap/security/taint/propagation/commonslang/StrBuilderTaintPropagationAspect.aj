package at.dallermassl.ap.security.taint.propagation.commonslang;

import org.apache.commons.lang.text.StrBuilder;

import at.dallermassl.ap.security.taint.extension.AbstractTaintedObjectAspect;
import at.dallermassl.ap.security.taint.extension.TaintedObject;

/**
 * Propagation aspect for org.apache.commons.lang.text.StrBuilder.StrBuilder
 * @author cdaller
 *
 */
public privileged aspect StrBuilderTaintPropagationAspect extends AbstractTaintedObjectAspect  {
    
//    /** Aspect for constructor {@link StringBuilder(CharSequence)} */    
//    after(CharSequence value) returning (StrBuilder returnObject): call(StrBuilder.new(CharSequence)) && args(value) {
//        if (value != null && value instanceof TaintedObject && ((TaintedObject)value).isTainted()) {
//            returnObject.setTainted(true);
//            returnObject.addTaintedSourceIdBits(((TaintedObject) value).getTaintedSourceIdBits());
//            returnObject.initTaintedObjectId();
//        }            
//    }
//
//    /** Aspect for constructor {@link StringBuilder(String)} */    
//    after(String value) returning (StrBuilder returnObject): call(StrBuilder.new(String)) && args(value) {
//        if (value != null && value.isTainted()) {
//            returnObject.setTainted(value.isTainted());
//            returnObject.addTaintedSourceIdBits(value.getTaintedSourceIdBits());
//            returnObject.initTaintedObjectId();
//        }
//    }
//    
//    /** Aspect for {@link StringBuilder#append(String)} */
//    after(String value, StrBuilder targetObject) returning (StrBuilder returnObject): 
//        call(public StringBuilder StrBuilder.append(String)) && args(value) && target(targetObject) {
//        if (value != null && value.isTainted()) {
//            returnObject.setTainted(true);
//            returnObject.addTaintedSourceIdBits(value.getTaintedSourceIdBits());
//            returnObject.initTaintedObjectId();
//        }
//        if (targetObject.isTainted()) {
//            returnObject.setTainted(true);
//            returnObject.addTaintedSourceIdBits(targetObject.getTaintedSourceIdBits());
//            returnObject.initTaintedObjectId();
//        }
//}
//    
//    /** Aspect for {@link StringBuilder#append(StringBuffer)} */
//    after(StringBuffer value, StrBuilder targetObject) returning (StrBuilder returnObject): 
//        call(public StrBuilder StrBuilder.append(StringBuffer)) && args(value) && target(targetObject) {
//        if (value != null && value.isTainted()) {
//            returnObject.setTainted(true);
//            returnObject.addTaintedSourceIdBits(value.getTaintedSourceIdBits());
//            returnObject.initTaintedObjectId();
//        }
//        if (targetObject.isTainted()) {
//            returnObject.setTainted(true);
//            returnObject.addTaintedSourceIdBits(targetObject.getTaintedSourceIdBits());
//            returnObject.initTaintedObjectId();
//        }
//    }
//
//    /** Aspect for {@link StringBuilder#append(StrBuilder)} */
//    after(StringBuffer value, StrBuilder targetObject) returning (StrBuilder returnObject): 
//        call(public StrBuilder StrBuilder.append(StrBuilder)) && args(value) && target(targetObject) {
//        if (value != null && value.isTainted()) {
//            returnObject.setTainted(true);
//            returnObject.addTaintedSourceIdBits(value.getTaintedSourceIdBits());
//            returnObject.initTaintedObjectId();
//        }
//        if (targetObject.isTainted()) {
//            returnObject.setTainted(true);
//            returnObject.addTaintedSourceIdBits(targetObject.getTaintedSourceIdBits());
//            returnObject.initTaintedObjectId();
//        }
//    }
//
//    /** Aspect for {@link StringBuilder#append(CharSequence)} */
//    after(CharSequence value, StringBuilder targetObject) returning (StringBuilder returnObject): 
//        call(public StringBuilder StringBuilder.append(CharSequence)) && args(value) && target(targetObject) {
//        if (value != null && value instanceof TaintedObject && ((TaintedObject)value).isTainted()) {
//            returnObject.setTainted(true);
//            returnObject.addTaintedSourceIdBits(((TaintedObject) value).getTaintedSourceIdBits());
//            returnObject.initTaintedObjectId();
//        }
//        if (targetObject.isTainted()) {
//            returnObject.setTainted(true);
//            returnObject.addTaintedSourceIdBits(targetObject.getTaintedSourceIdBits());
//            returnObject.initTaintedObjectId();
//        }
//    }
//
//    /** Aspect for {@link StringBuilder#insert(int, String)} */
//    after(int index, String value, StringBuilder targetObject) returning (StringBuilder returnObject): 
//        call(public StringBuilder StringBuilder.insert(int, String)) && args(index, value) && target(targetObject) {
//        if (value != null && value.isTainted()) {
//            returnObject.setTainted(true);
//            returnObject.addTaintedSourceIdBits(value.getTaintedSourceIdBits());
//            returnObject.initTaintedObjectId();
//        }
//        if (targetObject.isTainted()) {
//            returnObject.setTainted(true);
//            returnObject.addTaintedSourceIdBits(targetObject.getTaintedSourceIdBits());
//            returnObject.initTaintedObjectId();
//        }
//}
//
//    /** Aspect for {@link StringBuffer#replace(int, int String)} */
//    after(int index, int len, String value, StringBuilder targetObject) returning (StringBuilder returnObject): 
//        call(public StringBuilder StringBuilder.replace(int, int, String)) && args(index, len, value) && target(targetObject) {
//        if (value != null && value.isTainted()) {
//            returnObject.setTainted(true);
//            returnObject.addTaintedSourceIdBits(value.getTaintedSourceIdBits());
//            returnObject.initTaintedObjectId();
//        }
//        if (targetObject.isTainted()) {
//            returnObject.setTainted(true);
//            returnObject.addTaintedSourceIdBits(targetObject.getTaintedSourceIdBits());
//            returnObject.initTaintedObjectId();
//        }
//    }
//
//    
//    /** Aspect for {@link String#toString()} */
//    after(StringBuilder targetObject) returning (String returnObject): 
//        call(public String Object.toString()) && target(targetObject) && target(StringBuilder) {
//        returnObject.setTainted(targetObject.isTainted());
//        returnObject.addTaintedSourceIdBits(targetObject.getTaintedSourceIdBits());
//        returnObject.initTaintedObjectId();
//    }

}
