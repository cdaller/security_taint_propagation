/**
 * 
 */
package at.dallermassl.ap.security.taint.sink;

import org.aspectj.lang.JoinPoint;

/**
 * Defines the behavior when a tainted content is passed to an armoured sink.
 * 
 * @author cdaller
 */
public abstract aspect AbstractTaintedSinkAspect {

    private static boolean blockTainted = false;

    /**
     * Returns <code>true</code> if a sink should throw an exception when received tainted content.
     * @return <code>true</code> if a sink should throw an exception when received tainted content.
     */
    public static boolean isBlockTainted() {
        return blockTainted;
    }
    
    /**
     * If set to <code>true</code> an exception is thrown if a tainted string is passed to a sink. 
     * @param blockTainted if set to <code>true</code> an exception is thrown if a tainted string is 
     * passed to a sink.
     */
    public static void setBlockTainted(boolean blockTainted) {
        AbstractTaintedSinkAspect.blockTainted = blockTainted;
    }

    
    /**
     * Method called if a tainted value should be used.
     * @param value the value to be used.
     */
    public void handleTaintedSink(JoinPoint joinPoint, String value) {
        value.setTainted(false);        
        String message = "Tainted value will be printed in " + joinPoint.getSourceLocation() + ": '" + value + "'";
        if (isBlockTainted()) {
            value.setTainted(true);        
            throw new SecurityException(message);
        } else {
            System.err.println(message);
        }
        value.setTainted(true);        
    }

}
