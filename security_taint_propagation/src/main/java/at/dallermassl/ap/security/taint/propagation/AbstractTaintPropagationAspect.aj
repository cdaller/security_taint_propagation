package at.dallermassl.ap.security.taint.propagation;

import at.dallermassl.ap.security.taint.Configuration;
import at.dallermassl.ap.security.taint.composition.CompositionManager;
import at.dallermassl.ap.security.taint.composition.CompositionTreeNode;
import at.dallermassl.ap.security.taint.extension.TaintedObject;
import at.dallermassl.ap.security.taint.mbean.MBeanStartup;

public abstract aspect AbstractTaintPropagationAspect {

    static {
        MBeanStartup.startUp();
    }

    pointcut notInMyAdvice() : if(true);// : !within(CompositionManager) && !within(CompositionTreeNode);

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
        if (sourceObject.isTainted() && Configuration.isTaintCompositionEnabled()) {
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
                        && Configuration.isTaintCompositionEnabled()) {
            CompositionManager.getInstance().addCompositionNode(destinationObject, sourceObject);
            CompositionManager.getInstance().addCompositionNode(destinationObject, additionalObject);
        }
    }

}
