/**
 * 
 */
package at.dallermassl.ap.security.taint.extension;

import java.util.Set;

/**
 * @author cdaller
 *
 */
public interface TaintedObject {

    /**
     * @return the tainted.
     */
    boolean isTainted();
    /**
     * @param tainted the tainted to set.
     */
    void setTainted(boolean tainted);
    
    /**
     * Return the id of the tainted sources as a bit field (yes, I know, but I did not find another
     * possibility!!). 
     * @return the id of the tainted source.
     */
    int[] getTaintedSourceIds();

    int getTaintedSourceIdBits();

    /**
     * Set the id of the tainted source.
     * @param sourceId the id of the tainted source.
     */
    void addTaintedSourceId(int sourceId); 
    
    /**
     * Add all source ids in the given set.
     * @param sourceIds the ids to add.
     */
    void addTaintedSourceIds(int... sourceIds);

}
