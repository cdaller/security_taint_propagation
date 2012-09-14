/**
 * 
 */
package at.dallermassl.ap.security.taint.extension.java.lang;

/**
 * @author cdaller
 *
 */
public privileged aspect StringBuilderTaintedAspect {
    
    boolean StringBuilder.tainted = false;

    /**
     * @return the tainted.
     */
    public boolean StringBuilder.isTainted() {
        return tainted;
    }

    /**
     * @param tainted the tainted to set.
     */
    public void StringBuilder.setTainted(boolean tainted) {
//        System.out.println("set tainted to " + tainted);
        this.tainted = tainted;
    }
}
