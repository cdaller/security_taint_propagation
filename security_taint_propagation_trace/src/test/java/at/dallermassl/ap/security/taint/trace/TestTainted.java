package at.dallermassl.ap.security.taint.trace;

import at.dallermassl.ap.security.taint.extension.TaintedObject;

public class TestTainted implements TaintedObject {
    private boolean tainted;

    @Override
    public void addTaintedSourceId(int arg0) {
        // TODO Auto-generated method stub

    }

    @Override
    public void addTaintedSourceIdBits(int arg0) {
        // TODO Auto-generated method stub

    }

    @Override
    public void addTaintedSourceIds(int[] arg0) {
        // TODO Auto-generated method stub

    }

    @Override
    public void clearTaintedSourceIds() {
        // TODO Auto-generated method stub

    }

    @Override
    public int getTaintedObjectId() {
        // TODO Auto-generated method stub
        return 0;
    }

    @Override
    public int getTaintedSourceIdBits() {
        // TODO Auto-generated method stub
        return 0;
    }

    @Override
    public int[] getTaintedSourceIds() {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public boolean isTainted() {
        return tainted;
    }

    @Override
    public void setTainted(boolean arg0) {
        tainted = arg0;
    }


    @Override
    public void setTaintedSourceIdBits(int arg0) {
        // TODO Auto-generated method stub

    }

    @Override
    public void initTaintedObjectId() {
        // TODO Auto-generated method stub
        
    }

}
