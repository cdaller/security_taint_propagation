/**
 *
 */
package at.dallermassl.ap.security.taint.sink;

import org.aspectj.lang.JoinPoint;

import at.dallermassl.ap.security.taint.Configuration;
import at.dallermassl.ap.security.taint.composition.CompositionManager;
import at.dallermassl.ap.security.taint.extension.TaintedObject;
import at.dallermassl.ap.security.taint.source.TaintedSourceInfo;

/**
 * Defines the behavior when a tainted content is passed to an armoured sink.
 *
 * @author cdaller
 */
public abstract aspect AbstractTaintedSinkAspect {

    private static boolean blockTainted = false;
    private String sinkType;

    public AbstractTaintedSinkAspect() {
        this("unknown");
    }

    public AbstractTaintedSinkAspect(String sinkType) {
        this.sinkType = sinkType;
    }


    /**
     * Method called if a tainted value should be used.
     * @param joinPoint the joinPoint that triggered the taint event.
     * @param value the value to be used.
     */
    public void handleTaintedSink(JoinPoint joinPoint, TaintedObject value) {
        value.setTainted(false);
        int[] sourceIds = value.getTaintedSourceIds();
        StringBuilder sourceIdInfos = new StringBuilder();
        String prefix = "";
        for (int sourceId : sourceIds) {
            sourceIdInfos.append(prefix);
            sourceIdInfos.append(TaintedSourceInfo.getSourceInfo(sourceId));
            sourceIdInfos.append("(");
            sourceIdInfos.append(sourceId);
            sourceIdInfos.append(")");
            prefix = ", ";
        }
        StringBuilder messageBuilder = new StringBuilder("SECURITY-TAINT-WARNING: Tainted value will be used in a sink!");
        messageBuilder.append("[");
        messageBuilder.append(" type: ");
        messageBuilder.append(sinkType);
        messageBuilder.append(", sink code: ");
//        messageBuilder.append(joinPoint.getSourceLocation());
//        messageBuilder.append("/");
        messageBuilder.append(joinPoint.getSourceLocation().getWithinType().getCanonicalName());
        messageBuilder.append(":");
        messageBuilder.append(joinPoint.getSourceLocation().getLine());
        messageBuilder.append("/");
        messageBuilder.append(joinPoint.toShortString());
        messageBuilder.append(",");
        messageBuilder.append( "tainted sources: ");
        messageBuilder.append(sourceIdInfos);
        messageBuilder.append(",");
        messageBuilder.append(" value: '");
        messageBuilder.append(value);
        messageBuilder.append("'");
        if (Configuration.isTaintCompositionEnabled()) {
            messageBuilder.append("\n");
            messageBuilder.append(CompositionManager.getInstance().getCompositionString(value));
        }
        messageBuilder.append("]");
        value.setTainted(true);

        if (Configuration.isLogOnTaintedSink()) {
            System.err.println(messageBuilder.toString());
        }
        if (Configuration.isExceptionOnTaintedSink()) {
            throw new SecurityException(messageBuilder.toString());
        }
    }

}
