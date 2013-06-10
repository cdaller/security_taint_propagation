package at.dallermassl.ap.security.taint.composition;

import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import at.dallermassl.ap.security.taint.TaintPropagationPackage;
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
    private static final String PACKAGE_NAME_FILTER = TaintPropagationPackage.class.getPackage().getName();

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

    public void addCompositionNode(TaintedObject component, TaintedObject composite) {
        String stackTraceInfo = getStackTraceLine();
        CompositionTreeNode componentNode = getNode(component);
        componentNode.addSourceCodeInfo(stackTraceInfo);
        CompositionTreeNode compositeNode = getNode(composite);
        compositeNode.addSourceCodeInfo(stackTraceInfo);

        componentNode.addComposite(compositeNode);
    }

//    public void addCallerStackTrace(TaintedObject component) {
//        CompositionTreeNode node = retrieveNode(component, getStackTraceLine());
//    }


    private String getStackTraceLine() {
        String[] traces = TaintUtils.getStackTraceLines();
//        return traces[6];
        String trace;
        // start with 1 as first line is java.lang.Throwable
        for (int index = 1; index < traces.length; index++) {
            trace = traces[index];
            if (!trace.contains(PACKAGE_NAME_FILTER)) {
                return trace;
            }
        }
        return traces[0];
    }

    /**
     * Returns existing node or creates a new one and registers it.
     * @param component the component for the node.
     * @param stackTraceInfo the info of the source code.
     * @return the node (created or retrieved from map).
     */
    public CompositionTreeNode getNode(TaintedObject component) {
        int id = component.getTaintedObjectId();
        CompositionTreeNode node = traceMap.get(id);
        if (node == null) {
            // create new node:
            node = new CompositionTreeNode(id, component.toString());
            traceMap.put(id, node);
        } else {
            // change existing node:
            node.setComponentValue(component.toString());
        }
        return node;
    }

    public String getCompositionString(TaintedObject component) {
        // using printwriter to prevent taint propagation during creation of the output string :-(
        CompositionTreeNode node = traceMap.get(component.getTaintedObjectId());
        if (node == null) {
            return "no info available";
        }
//        addCallerStackTrace(component); // add stack trace line from last caller
        StringBuilder result = getCompositionString(node, new StringBuilder(), "", new HashSet<CompositionTreeNode>());
        return result.toString();
    }

    private StringBuilder getCompositionString(CompositionTreeNode componentNode, StringBuilder out, String prefix,
                    Set<CompositionTreeNode> allComposites) {
        out.append(prefix);
        out.append(componentNode.getNodeString());
        out.append("\n");
        // prevent infinite loop for self referencing nodes (only in one line in the tree):
        if (allComposites.contains(componentNode)) {
            out.append(prefix).append("  ").append("[self modificiation]").append("\n");
        } else {
            allComposites.add(componentNode);
            List<CompositionTreeNode> composites = componentNode.getComposites();
            for (CompositionTreeNode node : composites) {
                out = getCompositionString(node, out, prefix + "  ", allComposites);
            }
            allComposites.remove(componentNode);
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
    public void clear() {
        traceMap.clear();
    }
}

