package at.dallermassl.ap.security.taint.propagation;

import at.dallermassl.ap.security.taint.composition.CompositionManager;
import at.dallermassl.ap.security.taint.composition.CompositionTreeNode;

/**
 * @author cdaller
 *
 */
public privileged aspect StringBufferTaintPropagationAspect extends AbstractTaintPropagationAspect {

    /** Aspect for constructor {@link StringBuffer(CharSequence)} */
    after(CharSequence value) returning (StringBuffer returnObject):
        call(StringBuffer.new(CharSequence)) && args(value)
        && !within(CompositionManager) && !within(CompositionTreeNode) {
        propagateTainted(value, returnObject);
    }

    /** Aspect for constructor {@link StringBuffer(String)} */
    after(String value) returning (StringBuffer returnObject):
        call(StringBuffer.new(String)) && args(value)
        && !within(CompositionManager) && !within(CompositionTreeNode) {
        propagateTainted(value, returnObject);
    }

    /** Aspect for {@link StringBuffer#append(String)} */
    after(String value, StringBuffer targetObject) returning (StringBuffer returnObject):
        call(public StringBuffer StringBuffer.append(String)) && args(value) && target(targetObject)
        && !within(CompositionManager) && !within(CompositionTreeNode) {
        propagateTainted(targetObject, returnObject, value);
    }

    /** Aspect for {@link StringBuffer#append(StringBuffer)} */
    after(StringBuffer value, StringBuffer targetObject) returning (StringBuffer returnObject):
        call(public StringBuffer StringBuffer.append(StringBuffer)) && args(value) && target(targetObject)
        && !within(CompositionManager) && !within(CompositionTreeNode) {
        propagateTainted(targetObject, returnObject, value);
    }

    /** Aspect for {@link StringBuffer#insert(int, String)} */
    after(int index, String value, StringBuffer targetObject) returning (StringBuffer returnObject):
        call(public StringBuffer StringBuffer.insert(int, String)) && args(index, value) && target(targetObject)
        && !within(CompositionManager) && !within(CompositionTreeNode) {
        propagateTainted(targetObject, returnObject, value);
    }

    /** Aspect for {@link StringBuffer#replace(int, int String)} */
    after(int index, int len, String value, StringBuffer targetObject) returning (StringBuffer returnObject):
        call(public StringBuffer StringBuffer.replace(int, int, String)) &&
        args(index, len, value) && target(targetObject)
        && !within(CompositionManager) && !within(CompositionTreeNode) {
        propagateTainted(targetObject, returnObject, value);
    }

    /** Aspect for {@link String#toString()} */
    after(StringBuffer targetObject) returning (String returnObject):
        call(public String Object.toString()) && target(targetObject) && target(java.lang.StringBuffer)
        && !within(CompositionManager) && !within(CompositionTreeNode) {
        propagateTainted(targetObject, returnObject);
    }

}
