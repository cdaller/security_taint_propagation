/**
 * 
 */
package at.dallermassl.ap.security.taint.extension;


/**
 * Interface for Taint information for String or similar objects. This interface allows to get/set
 * the tainted flag and to set/get some additional information of the taintedness.
 * 
 * The system follows the paper described by Vivek Haldar, Deepak Chandra, Michael Franz: 
 * Dynamic Taint Propagation for Java (http://www.acsac.org/2005/papers/45.pdf)
 * 
 * @author cdaller
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
     * Return the id of the tainted sources as a bit field.
     * @return the ids of the tainted source as an int array.
     */
    int[] getTaintedSourceIds();

    /**
     * Returns the 32bit mask holding the source ids -  (yes, I know, but I did not find another
     * possibility!! 
     * @return the 32bit mask holding the source ids.
     */
    int getTaintedSourceIdBits();
    
    /**
     * Adds all source ids given in the 32bit mask.
     * @param sourceIds the 32bit mask to add.
     */
    void addTaintedSourceIdBits(int sourceIds);
    
    /**
     * Sets (not adds) the given source ids given in the 32bit mask.
     * @param sourceIds the 32bit mask to set.
     */
    void setTaintedSourceIdBits(int sourceIds);

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
    
    /**
     * Removes all tainted source ids.
     */
    void clearTaintedSourceIds();

}
