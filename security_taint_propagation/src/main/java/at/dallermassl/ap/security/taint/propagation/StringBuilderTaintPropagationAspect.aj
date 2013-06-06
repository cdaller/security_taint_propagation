package at.dallermassl.ap.security.taint.propagation;

import at.dallermassl.ap.security.taint.Configuration;
import at.dallermassl.ap.security.taint.composition.CompositionManager;
import at.dallermassl.ap.security.taint.composition.CompositionTreeNode;
import at.dallermassl.ap.security.taint.extension.TaintedObject;

/**
 * @author cdaller
 *
 */
public privileged aspect StringBuilderTaintPropagationAspect {


    /** Aspect for constructor {@link StringBuilder(CharSequence)} */
    after(CharSequence value) returning (StringBuilder returnObject):
        call(StringBuilder.new(CharSequence)) && args(value) && !within(CompositionManager) {
        if (value != null && value instanceof TaintedObject && ((TaintedObject)value).isTainted()) {
            returnObject.setTainted(true);
            returnObject.addTaintedSourceIdBits(((TaintedObject) value).getTaintedSourceIdBits());
            if (Configuration.TAINTED_COMPOSITION_TRACE_ENABLED) {
                CompositionManager.getInstance().addCompositionNode(returnObject, (TaintedObject) value);
            }
        }
    }

    /** Aspect for constructor {@link StringBuilder(String)} */
    after(String value) returning (StringBuilder returnObject):
        call(StringBuilder.new(String)) && args(value) && !within(CompositionManager) {
        if (value != null && value.isTainted()) {
            returnObject.setTainted(true);
            returnObject.addTaintedSourceIdBits(value.getTaintedSourceIdBits());
            if (Configuration.TAINTED_COMPOSITION_TRACE_ENABLED) {
                CompositionManager.getInstance().addCompositionNode(returnObject, value);
            }
        }
    }

    /** Aspect for {@link StringBuilder#append(String)} */
    after(String value, StringBuilder targetObject) returning (StringBuilder returnObject):
        call(public StringBuilder StringBuilder.append(String)) && args(value) && target(targetObject)
        && !within(CompositionManager) {
        if (value != null && value.isTainted()) {
            returnObject.setTainted(true);
            returnObject.addTaintedSourceIdBits(value.getTaintedSourceIdBits());
            if (Configuration.TAINTED_COMPOSITION_TRACE_ENABLED) {
                CompositionManager.getInstance().addCompositionNode(returnObject, value);
            }
        }
        if (targetObject.isTainted()) {
            returnObject.setTainted(true);
            returnObject.addTaintedSourceIdBits(targetObject.getTaintedSourceIdBits());
            if (Configuration.TAINTED_COMPOSITION_TRACE_ENABLED) {
                CompositionManager.getInstance().addCompositionNode(returnObject, targetObject);
            }
        }
}

    /** Aspect for {@link StringBuilder#append(StringBuffer)} */
    after(StringBuffer value, StringBuilder targetObject) returning (StringBuilder returnObject):
        call(public StringBuilder StringBuilder.append(StringBuffer)) && args(value) && target(targetObject)
        && !within(CompositionManager) {
        if (value != null && value.isTainted()) {
            returnObject.setTainted(true);
            returnObject.addTaintedSourceIdBits(value.getTaintedSourceIdBits());
            if (Configuration.TAINTED_COMPOSITION_TRACE_ENABLED) {
                CompositionManager.getInstance().addCompositionNode(returnObject, value);
            }
        }
        if (targetObject.isTainted()) {
            returnObject.setTainted(true);
            returnObject.addTaintedSourceIdBits(targetObject.getTaintedSourceIdBits());
            if (Configuration.TAINTED_COMPOSITION_TRACE_ENABLED) {
                CompositionManager.getInstance().addCompositionNode(returnObject, targetObject);
            }
        }
    }

    /** Aspect for {@link StringBuilder#append(CharSequence)} */
    after(CharSequence value, StringBuilder targetObject) returning (StringBuilder returnObject):
        call(public StringBuilder StringBuilder.append(CharSequence)) && args(value) && target(targetObject)
        && !within(CompositionManager) {
        if (value != null && value instanceof TaintedObject && ((TaintedObject)value).isTainted()) {
            returnObject.setTainted(true);
            returnObject.addTaintedSourceIdBits(((TaintedObject) value).getTaintedSourceIdBits());
            if (Configuration.TAINTED_COMPOSITION_TRACE_ENABLED) {
                CompositionManager.getInstance().addCompositionNode(returnObject, (TaintedObject) value);
            }
        }
        if (targetObject.isTainted()) {
            returnObject.setTainted(true);
            returnObject.addTaintedSourceIdBits(targetObject.getTaintedSourceIdBits());
            if (Configuration.TAINTED_COMPOSITION_TRACE_ENABLED) {
                CompositionManager.getInstance().addCompositionNode(returnObject, targetObject);
            }
        }
    }

    /** Aspect for {@link StringBuilder#insert(int, String)} */
    after(int index, String value, StringBuilder targetObject) returning (StringBuilder returnObject):
        call(public StringBuilder StringBuilder.insert(int, String)) && args(index, value) && target(targetObject)
        && !within(CompositionManager) {
        if (value != null && value.isTainted()) {
            returnObject.setTainted(true);
            returnObject.addTaintedSourceIdBits(value.getTaintedSourceIdBits());
            if (Configuration.TAINTED_COMPOSITION_TRACE_ENABLED) {
                CompositionManager.getInstance().addCompositionNode(returnObject, value);
            }
        }
        if (targetObject.isTainted()) {
            returnObject.setTainted(true);
            returnObject.addTaintedSourceIdBits(targetObject.getTaintedSourceIdBits());
            if (Configuration.TAINTED_COMPOSITION_TRACE_ENABLED) {
                CompositionManager.getInstance().addCompositionNode(returnObject, targetObject);
            }
        }
}

    /** Aspect for {@link StringBuffer#replace(int, int String)} */
    after(int index, int len, String value, StringBuilder targetObject) returning (StringBuilder returnObject):
        call(public StringBuilder StringBuilder.replace(int, int, String))
        && args(index, len, value)
        && target(targetObject)
        && !within(CompositionManager) {
        if (value != null && value.isTainted()) {
            returnObject.setTainted(true);
            returnObject.addTaintedSourceIdBits(value.getTaintedSourceIdBits());
            if (Configuration.TAINTED_COMPOSITION_TRACE_ENABLED) {
                CompositionManager.getInstance().addCompositionNode(returnObject, value);
            }
        }
        if (targetObject.isTainted()) {
            returnObject.setTainted(true);
            returnObject.addTaintedSourceIdBits(targetObject.getTaintedSourceIdBits());
            if (Configuration.TAINTED_COMPOSITION_TRACE_ENABLED) {
                CompositionManager.getInstance().addCompositionNode(returnObject, targetObject);
            }
        }
    }


    /** Aspect for {@link String#toString()} */
    after(StringBuilder targetObject) returning (String returnObject):
        call(public String Object.toString())
        && target(targetObject)
        && target(StringBuilder)
        && !within(CompositionManager) && !within(CompositionTreeNode){
        returnObject.setTainted(targetObject.isTainted());
        returnObject.addTaintedSourceIdBits(targetObject.getTaintedSourceIdBits());
        if (Configuration.TAINTED_COMPOSITION_TRACE_ENABLED) {
            CompositionManager.getInstance().addCompositionNode(returnObject, targetObject);
        }
    }

}
