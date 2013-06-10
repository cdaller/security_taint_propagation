package at.dallermassl.ap.security.taint.composition;

import java.util.ArrayList;
import java.util.List;

public class CompositionTreeNode {
    private int objectId;
    private String componentValue;
    private List<String> sourceCodeInfos; // TODO: better datastructure, stacktrace??
    private List<CompositionTreeNode> composites;


    public CompositionTreeNode(int objectId, String componentValue) {
        this(objectId, componentValue, null);
    }

    public CompositionTreeNode(int objectId, String componentValue, String sourceCodeInfo) {
        super();
        this.objectId = objectId;
        this.componentValue = componentValue;
        sourceCodeInfos = new ArrayList<String>();
        if (sourceCodeInfo != null) {
            sourceCodeInfos.add(sourceCodeInfo);
        }
        composites = new ArrayList<CompositionTreeNode>();
    }


    public int getObjectId() {
        return objectId;
    }


    public void setObjectId(int objectId) {
        this.objectId = objectId;
    }


    public String getComponentValue() {
        return componentValue;
    }


    public void setComponentValue(String componentValue) {
        this.componentValue = componentValue;
    }


    public List<String> getSourceCodeInfos() {
        return sourceCodeInfos;
    }


    public void addSourceCodeInfo(String sourceCodeInfo) {
        sourceCodeInfos.add(sourceCodeInfo);
    }

    public void addComposite(CompositionTreeNode composite) {
        composites.add(composite);
    }

    /**
     * Returns the list of composites or an empty list.
     * @return the list of composites or an empty list.
     */
    public List<CompositionTreeNode> getComposites() {
        return composites;
    }

    /**
     * Returns a string representation of the node (not as debuggy as toString()).
     * @return a string representation of the node (not as debuggy as toString()).
     */
    public String getNodeString() {
        StringBuilder builder = new StringBuilder();
        builder.append("\"");
        builder.append(componentValue);
        builder.append("\"").append(" (").append(objectId).append(") ");
        if (objectId == 0) {
            builder.append("not tainted");
        } else {
            builder.append("TAINTED!");
        }
        builder.append(" modified at ").append(sourceCodeInfos);
        return builder.toString();
    }


    @Override
    public String toString() {
        List<Integer> compositeIds = new ArrayList<Integer>();
        for (CompositionTreeNode compositeNode : composites) {
            compositeIds.add(compositeNode.getObjectId());
        }
        return "CompositionTreeNode [componentValue=" + componentValue
                        + ", objectId=" + objectId
                        + ", composites =" + compositeIds
                        + ", sourceCodeInfos=" + sourceCodeInfos
                        + "]";
    }






}
