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

    /**
     * Returns the 32bit mask holding the source ids.
     * @return the 32bit mask holding the source ids.
     */
    int getTaintedSourceIdBits();
    
    /**
     * Adds all source ids given in the 32bit mask.
     * @param sourceIds the 32bit mask to add.
     */
    void addTaintedSourceIdBits(int sourceIds);

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
