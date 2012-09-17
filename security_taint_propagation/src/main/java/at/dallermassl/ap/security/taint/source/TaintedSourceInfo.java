/**
 * 
 */
package at.dallermassl.ap.security.taint.source;

import java.util.HashMap;
import java.util.Map;

/**
 * @author cdaller
 *
 */
public class TaintedSourceInfo {
    private static int nextId = 1;
    private static Map<Integer, String> infoMap = new HashMap<Integer, String>();
    
    /**
     * Return the next free id for source infos.
     * @return the next free id for source infos.
     */
    public static int getNextId() {
        return nextId++;
    }
    
    /**
     * Add a source info and returns the id for it that should be used for all these source info.
     * @param info the info to be added.
     * @return the id of the info.
     */
    public static int addSourceInfo(String info) {
        int id = getNextId();
        addSourceInfo(id, info);
        return id;
    }
    
    /**
     * Adds an info for the given id.
     * @param id the id of the info.
     * @param info the info.
     * @throws IllegalArgumentException if the id was already used before.
     */
    public static void addSourceInfo(int id, String info) {
        if (infoMap.containsKey(id)) {
            throw new IllegalArgumentException("TaintedSourceInfo: id " + id + " was already added before!");
        }
        if (info == null) {
            throw new IllegalArgumentException("TaintedSourceInfo: Info must not be null!");
        }
        infoMap.put(id, info);
    }
    
    /**
     * Returns the info that was stored under the given id or null if nothing was stored.
     * @param id the id of the info.
     * @return the info that was stored under the given id or null if nothing was stored.
     */
    public static String getSourceInfo(int id) {
        return infoMap.get(id);
    }

}
