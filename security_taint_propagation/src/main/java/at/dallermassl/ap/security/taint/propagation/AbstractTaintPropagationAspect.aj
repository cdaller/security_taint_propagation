package at.dallermassl.ap.security.taint.propagation;

import at.dallermassl.ap.security.taint.Configuration;
import at.dallermassl.ap.security.taint.composition.CompositionManager;
import at.dallermassl.ap.security.taint.extension.TaintedObject;

public abstract aspect AbstractTaintPropagationAspect {

    public void propagateTainted(CharSequence sourceObject, TaintedObject destinationObject) {
        if (sourceObject != null && sourceObject instanceof TaintedObject) {
            propagateTaintedInternal((TaintedObject) sourceObject, destinationObject);
        }
    }

    public void propagateTainted(TaintedObject sourceObject, TaintedObject destinationObject, CharSequence additionalObject) {
        if (additionalObject instanceof TaintedObject) {
            propagateTaintedInternal(sourceObject, destinationObject, (TaintedObject) additionalObject);
        } else {
            propagateTaintedInternal(sourceObject, destinationObject);
        }
    }

    private void propagateTaintedInternal(TaintedObject sourceObject, TaintedObject destinationObject) {
        if (sourceObject.isTainted()) {
            destinationObject.setTainted(true);
            destinationObject.addTaintedSourceIdBits(sourceObject.getTaintedSourceIdBits());
        }
        if (sourceObject.isTainted() && Configuration.TAINTED_COMPOSITION_TRACE_ENABLED) {
            CompositionManager.getInstance().addCompositionNode(destinationObject, sourceObject);
        }
    }

    private void propagateTaintedInternal(TaintedObject sourceObject, TaintedObject destinationObject, TaintedObject additionalObject) {
        if (additionalObject != null && additionalObject.isTainted()) {
            destinationObject.setTainted(true);
            destinationObject.addTaintedSourceIdBits(additionalObject.getTaintedSourceIdBits());
        }
        if (sourceObject.isTainted()) {
            destinationObject.setTainted(true);
            destinationObject.addTaintedSourceIdBits(sourceObject.getTaintedSourceIdBits());
        }
        if ((sourceObject.isTainted() || (additionalObject !=null && additionalObject.isTainted()))
                        && Configuration.TAINTED_COMPOSITION_TRACE_ENABLED) {
            CompositionManager.getInstance().addCompositionNode(destinationObject, sourceObject);
            CompositionManager.getInstance().addCompositionNode(destinationObject, additionalObject);
        }
    }

}
