/**
 * 
 */
package at.dallermassl.ap.security.taint.sink.io;

import at.dallermassl.ap.security.taint.sink.AbstractTaintedSinkAspect;

/**
 * @author cdaller
 * Sinks: Statement.executeQuery(), JspWriter.print(), new File(), Runtime.exec(), ...
 */
public aspect ProcessExecutorSinkAspect extends AbstractTaintedSinkAspect {
    
    before(String cmd): call(public void Runtime.exec(String)) && args(cmd) {
        if (cmd != null && cmd.isTainted()) {
            handleTaintedSink(thisJoinPoint, cmd);
        }
    }

    before(String cmd, String[] envp): call(public void Runtime.exec(String, String[], ..)) && args(cmd, envp, ..) {
        if (cmd != null && cmd.isTainted()) {
            handleTaintedSink(thisJoinPoint, cmd);
        }
        for (String env : envp) {
            if (env != null && env.isTainted()) {
                handleTaintedSink(thisJoinPoint, env);
            }
        }
    }

    before(String[] cmds): call(public void Runtime.exec(String[])) && args(cmds) {
        for (String cmd : cmds) {
            if (cmd != null && cmd.isTainted()) {
                handleTaintedSink(thisJoinPoint, cmd);
            }
        }
    }

    before(String[] cmds, String[] envp): call(public void Runtime.exec(String[], String[], ..)) && args(cmds, envp, ..) {
        for (String cmd : cmds) {
            if (cmd != null && cmd.isTainted()) {
                handleTaintedSink(thisJoinPoint, cmd);
            }
        }
        for (String env : envp) {
            if (env != null && env.isTainted()) {
                handleTaintedSink(thisJoinPoint, env);
            }
        }
    }
    
    /** Aspect for constructor {@link ProcessBuilder(String)} */    
    after(String[] values) returning (ProcessBuilder returnObject): args(values) && (
                    call(ProcessBuilder.new(String...)) 
                    ) {
        for (String cmd : values) {
            if (cmd != null && cmd.isTainted()) {
                handleTaintedSink(thisJoinPoint, cmd);
            }
        }
    }


}
