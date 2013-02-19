package at.dallermassl.ap.security.taint.trace;

import at.dallermassl.ap.security.taint.extension.TaintedObject;


public aspect PerObjAspect perthis(setTaintedExecution(TaintedObject, boolean)) {
    private static int count = 0;
    private int index;
    
    
    public PerObjAspect() {
        System.out.println("Create perObject Aspect instance");
    }
    
    pointcut setTaintedExecution(TaintedObject taintedObject, boolean value) 
       : execution(* *.setTainted(boolean)) && args(value) && target(taintedObject); 
    
    before(TaintedObject taintedObject, boolean value)
       : setTaintedExecution(taintedObject, value) {
        if (value) {
            index = count++;
        }
    }
        
    public int getIndex() {
        return index;
    }

}
