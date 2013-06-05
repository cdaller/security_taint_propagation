package at.dallermassl.ap.security.taint.composition;

import java.io.PrintWriter;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import at.dallermassl.ap.security.taint.extension.TaintedObject;
import at.dallermassl.ap.security.taint.util.TaintUtils;

/**
 * Stores information about composition of tainted objects using their object ids.
 * @author christof.dallermassl
 *
 */
public class CompositionManager {

    /** Stores information about composition of the objects. */
    private static Map<Integer, CompositionTreeNode> traceMap = new HashMap<Integer, CompositionTreeNode>();

    private static CompositionManager instance;

    private CompositionManager() {
    }

    /**
     * Returns the singleton instance of the composition manager.
     * @return the singleton instance of the composition manager.
     */
    public static CompositionManager getInstance() {
        if (instance == null) {
            instance = new CompositionManager();
        }
        return instance;
    }

    public void addCompositionNode(TaintedObject component, TaintedObject composite, String operation) {
        String stackTraceInfo = TaintUtils.getStackTraceLines()[5]; // FIXME: hack: hardcoded line
        CompositionTreeNode componentNode = getNode(component, stackTraceInfo);
        CompositionTreeNode compositeNode = getNode(composite, stackTraceInfo);
        componentNode.addComposite(compositeNode);
    }

    /**
     * Returns existing node or creates a new one and registers it.
     * @param component the component for the node.
     * @param stackTraceInfo the info of the source code.
     * @return the node (created or retrieved from map).
     */
    protected CompositionTreeNode getNode(TaintedObject component, String stackTraceInfo) {
        int id = component.getTaintedObjectId();
        CompositionTreeNode node = traceMap.get(id);
        if (node == null) {
            // create new node:
            node = new CompositionTreeNode(id, component.toString(), stackTraceInfo);
            traceMap.put(id, node);
        } else {
            // change existing node:
            node.setComponentValue(component.toString());
            node.setSourceCodeInfo(stackTraceInfo);
        }
        return node;
    }

    public String getCompositionString(TaintedObject component) {
        // using printwriter to prevent taint propagation during creation of the output string :-(
        CompositionTreeNode node = traceMap.get(component.getTaintedObjectId());
        if (node == null) {
            return "no info available";
        }
        StringBuilder result = getCompositionString(node, new StringBuilder(), "");
        return result.toString();
    }

    protected StringBuilder getCompositionString(CompositionTreeNode componentNode, StringBuilder out, String prefix) {
        out.append(prefix);
        out.append(componentNode);
        out.append("\n");
        List<CompositionTreeNode> composites = componentNode.getComposites();
        for (CompositionTreeNode node : composites) {
            out = getCompositionString(node, out, prefix + "  ");
        }
        return out;
    }

//    /**
//     * Add the id of a composite object to the list of object ids.
//     * @param objectId the object that is composed of multiple composites.
//     * @param componentObjectId the id of the composite.
//     */
//    public static void addComposite(int objectId, int componentObjectId) {
//        Set<Integer> ids = traceMap.get(objectId);
//        if (ids == null) {
//            ids = new HashSet<Integer>();
//            traceMap.put(objectId, ids);
//        }
//        System.out.println("adding compositeid " + componentObjectId + " to objectid " + objectId);
//        ids.add(componentObjectId); // as it is a set, we can add it without checking (faster)
//    }
//
//    /**
//     * Returns a set of composite ids or an empty Set if the object does not have any composites.
//     * @param objectId the id of the object.
//     * @return a set of composite ids or an empty Set if the object does not have any composites.
//     */
//    public static Set<Integer> getComposites(int objectId) {
//        return getComposites(objectId, new HashSet<Integer>());
//    }
//
//    private static Set<Integer> getComposites(int objectId, Set<Integer> result) {
//        Set<Integer> ids = traceMap.get(objectId);
//        if (ids == null || ids.isEmpty()) {
//            return result;
//        }
//        for (int id : ids) {
//            result = getComposites(id, result);
//            result.add(id);
//        }
//        return result;
//    }

    /**
     * Clears all stored composition mappings.
     */
    protected void clear() {
        System.out.println("--------");
        traceMap.clear();
    }
}

