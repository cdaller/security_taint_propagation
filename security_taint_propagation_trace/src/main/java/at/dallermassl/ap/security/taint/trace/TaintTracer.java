package at.dallermassl.ap.security.taint.trace;

import java.io.PrintStream;
import java.util.List;
import java.util.WeakHashMap;

import org.aspectj.lang.JoinPoint;

import at.dallermassl.ap.security.taint.extension.TaintedObject;

public class TaintTracer {
    private WeakHashMap<TaintedObject, TraceInfo> map = new WeakHashMap<TaintedObject, TraceInfo>();
    private static TaintTracer instance;
    
    private TaintTracer() {
    }
    
    public static TaintTracer getInstance() {
        if (instance == null) {
            instance = new TaintTracer();
        }
        return instance;
    }
    
    public void addEnter(TaintedObject taintedObject, JoinPoint joinPoint) {
        getTraceInfo(taintedObject).addEnter(joinPoint);
    }
        
    public void addExit(TaintedObject taintedObject, JoinPoint joinPoint) {
        getTraceInfo(taintedObject).addExit(joinPoint, taintedObject);
    }
    
    /**
     * @param taintedObject
     * @return
     */
    private TraceInfo getTraceInfo(TaintedObject taintedObject) {
        TraceInfo traceInfo = map.get(taintedObject);
        if (traceInfo == null) {
            traceInfo = new TraceInfo();
            map.put(taintedObject, traceInfo);
        }
        return traceInfo;
    }
    
    public TraceInfo getTraceInfos(TaintedObject object) {
        return map.get(object);
    }
    
    public void printInfos(TaintedObject object, PrintStream out) {
        TraceInfo info = getTraceInfos(object);
        if (info != null) {
            List<String> traces = info.getTraces();
            for (String trace : traces) {
                out.println(trace);
            }
        }
    }
}
