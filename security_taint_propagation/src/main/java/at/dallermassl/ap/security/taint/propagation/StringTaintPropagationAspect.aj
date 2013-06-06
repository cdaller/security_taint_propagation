package at.dallermassl.ap.security.taint.propagation;

import java.util.Locale;

import at.dallermassl.ap.security.taint.Configuration;
import at.dallermassl.ap.security.taint.composition.CompositionManager;
import at.dallermassl.ap.security.taint.extension.TaintedObject;

/**
 * @author cdaller
 *
 */
public privileged aspect StringTaintPropagationAspect {

    /** Aspect for constructor {@link String(String)} or methods using a string as param */
    after(String value) returning (String returnObject):
    args(value) && !within(CompositionManager) && (
    call(String.new(String))) {
        if (value != null) {
            if (value.isTainted()) {
                returnObject.setTainted(true);
                returnObject.addTaintedSourceIdBits(value.getTaintedSourceIdBits());
                if (Configuration.TAINTED_COMPOSITION_TRACE_ENABLED) {
                    CompositionManager.getInstance().addCompositionNode(returnObject, value);
                }
            }
        }
    }

    /** Aspect for methods using a string as param */
    after(String value, String targetObject) returning (String returnObject):
    args(value) && target(targetObject) && !within(CompositionManager) && (
    call(public String String.concat(String))) {
        if (value != null) {
            boolean tainted = value.isTainted() || targetObject.isTainted();
            if (tainted) {
                returnObject.setTainted(true);
                returnObject.addTaintedSourceIdBits(value.getTaintedSourceIdBits());
                returnObject.addTaintedSourceIdBits(targetObject.getTaintedSourceIdBits());
                if (Configuration.TAINTED_COMPOSITION_TRACE_ENABLED) {
                    CompositionManager.getInstance().addCompositionNode(returnObject, targetObject);
                    CompositionManager.getInstance().addCompositionNode(returnObject, value);
                }
            }
        }
    }

    /** Aspect for {@link String#toString() or similar} */
    after(String targetObject) returning (String returnObject):
    target(targetObject) && target(java.lang.String) &&
    !within(CompositionManager) && (
      call(public String Object.toString()) ||
      call(public String String.trim()) ||
      call(public String String.toLowerCase()) ||
      call(public String String.toLowerCase(Locale)) ||
      call(public String String.toUpperCase()) ||
      call(public String String.toUpperCase(Locale)) ||
      call(public String String.substring(..))
    ) {
        if (targetObject != null && targetObject.isTainted()) {
            returnObject.setTainted(true);
            returnObject.addTaintedSourceIdBits(targetObject.getTaintedSourceIdBits());
            if (Configuration.TAINTED_COMPOSITION_TRACE_ENABLED) {
                CompositionManager.getInstance().addCompositionNode(returnObject, targetObject);
            }
        }
    }

    /** Aspect for {@link CharSequence#subSequence()} */
    after(TaintedObject targetObject) returning (TaintedObject returnObject):
    target(targetObject) && !within(CompositionManager) && (
      call(public CharSequence CharSequence.subSequence(..))
    ) {
        if (targetObject != null && targetObject.isTainted() && returnObject instanceof TaintedObject) {
            returnObject.setTainted(true);
            returnObject.addTaintedSourceIdBits(targetObject.getTaintedSourceIdBits());
            if (Configuration.TAINTED_COMPOSITION_TRACE_ENABLED) {
                CompositionManager.getInstance().addCompositionNode(returnObject, targetObject);
            }
        }
    }

    /** Aspect for {@link String#toString() or similar} */
    after(String targetObject) returning (String[] returnObjects):
    target(targetObject) && !within(CompositionManager) && (
      call(public String[] String.split(String)) ||
      call(public String[] String.split(String, int))
    ) {
        if (targetObject.isTainted()) {
            for (String returnObject : returnObjects) {
                returnObject.setTainted(true);
                returnObject.addTaintedSourceIdBits(targetObject.getTaintedSourceIdBits());
                if (Configuration.TAINTED_COMPOSITION_TRACE_ENABLED) {
                    CompositionManager.getInstance().addCompositionNode(returnObject, targetObject);
                }
            }
        }
    }

    /** Aspect for methods using a string as param */
    after(String targetObject) returning (String returnObject):
    target(targetObject) && !within(CompositionManager) && (
      call(public String String.replace(char, char))
    ) {
        if (targetObject.isTainted()) {
            returnObject.setTainted(true);
            returnObject.addTaintedSourceIdBits(targetObject.getTaintedSourceIdBits());
            if (Configuration.TAINTED_COMPOSITION_TRACE_ENABLED) {
                CompositionManager.getInstance().addCompositionNode(returnObject, targetObject);
            }
        }
    }

    /** Aspect for methods using a string as param */
    after(CharSequence regexp, CharSequence replacement, String targetObject) returning (String returnObject):
      args(regexp, replacement) && target(targetObject) &&
      !within(CompositionManager) &&
      call(public String String.replace(CharSequence, CharSequence)) {
        // <FIXXME date="04.06.2013" author="christof.dallermassl">
        // FIXME: does not work if the regular expression replacement uses back references that return a tainted string!
        if (replacement != null && replacement instanceof TaintedObject) {
            boolean tainted = ((TaintedObject) replacement).isTainted() || targetObject.isTainted();
            if (tainted) {
                returnObject.setTainted(true);
                returnObject.addTaintedSourceIdBits(((TaintedObject) replacement).getTaintedSourceIdBits());
                returnObject.addTaintedSourceIdBits(targetObject.getTaintedSourceIdBits());
                if (Configuration.TAINTED_COMPOSITION_TRACE_ENABLED) {
                    if (targetObject.isTainted()) {
                        CompositionManager.getInstance().addCompositionNode(returnObject, targetObject);
                    }
                    if (((TaintedObject) replacement).isTainted()) {
                        CompositionManager.getInstance().addCompositionNode(returnObject, (TaintedObject) replacement);
                    }
                }
            }
            // </FIXXME>
        }
    }

    /** Aspect for methods using a string as param */
    after(CharSequence regexp, CharSequence replacement, String targetObject) returning (String returnObject):
      args(regexp, replacement) && target(targetObject) &&
      !within(CompositionManager) && (
        call(public String String.replaceAll(String, String)) ||
        call(public String String.replaceFirst(String, String))
      ) {
        if (replacement != null && replacement instanceof TaintedObject) {
            boolean tainted = ((TaintedObject) replacement).isTainted() || targetObject.isTainted();
            if (tainted) {
                returnObject.setTainted(true);
                returnObject.addTaintedSourceIdBits(((TaintedObject) replacement).getTaintedSourceIdBits());
                returnObject.addTaintedSourceIdBits(targetObject.getTaintedSourceIdBits());
                if (Configuration.TAINTED_COMPOSITION_TRACE_ENABLED) {
                    if (targetObject.isTainted()) {
                        CompositionManager.getInstance().addCompositionNode(returnObject, targetObject);
                    }
                    if (((TaintedObject) replacement).isTainted()) {
                        CompositionManager.getInstance().addCompositionNode(returnObject, (TaintedObject) replacement);
                    }
                }
            }
        }
    }

}
