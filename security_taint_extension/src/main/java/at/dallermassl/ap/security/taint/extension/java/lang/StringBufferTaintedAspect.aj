/**
 * 
 */
package at.dallermassl.ap.security.taint.extension.java.lang;

/**
 * @author cdaller
 *
 */
public privileged aspect StringBufferTaintedAspect {
    
    boolean StringBuffer.tainted = false;

    /**
     * @return the tainted.
     */
    public boolean StringBuffer.isTainted() {
        return tainted;
    }

    /**
     * @param tainted the tainted to set.
     */
    public void StringBuffer.setTainted(boolean tainted) {
//        System.out.println("set tainted to " + tainted);
        this.tainted = tainted;
    }
}
