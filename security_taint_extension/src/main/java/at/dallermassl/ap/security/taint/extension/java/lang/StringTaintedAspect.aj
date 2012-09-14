/**
 * 
 */
package at.dallermassl.ap.security.taint.extension.java.lang;

/**
 * @author cdaller
 *
 */
public privileged aspect StringTaintedAspect {
            
    boolean String.tainted = false;

    /**
     * @return the tainted.
     */
    public boolean String.isTainted() {
        return tainted;
    }

    /**
     * @param tainted the tainted to set.
     */
    public void String.setTainted(boolean tainted) {
//        System.out.println("set tainted to " + tainted);
        this.tainted = tainted;
    }
}
