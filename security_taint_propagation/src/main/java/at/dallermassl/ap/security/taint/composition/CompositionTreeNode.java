package at.dallermassl.ap.security.taint.composition;

import java.util.ArrayList;
import java.util.List;

public class CompositionTreeNode {
    private int objectId;
    private String componentValue;
    private String sourceCodeInfo; // TODO: better datastructure, stacktrace??
    private List<CompositionTreeNode> composites;


    public CompositionTreeNode(int objectId, String componentValue, String sourceCodeInfo) {
        super();
        this.objectId = objectId;
        this.componentValue = componentValue;
        this.sourceCodeInfo = sourceCodeInfo;
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


    public String getSourceCodeInfo() {
        return sourceCodeInfo;
    }


    public void setSourceCodeInfo(String sourceCodeInfo) {
        this.sourceCodeInfo = sourceCodeInfo;
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


    @Override
    public String toString() {
        return "CompositionTreeNode [componentValue=" + componentValue + ", objectId=" + objectId + ", sourceCodeInfo="
                        + sourceCodeInfo + "]";
    }






}
