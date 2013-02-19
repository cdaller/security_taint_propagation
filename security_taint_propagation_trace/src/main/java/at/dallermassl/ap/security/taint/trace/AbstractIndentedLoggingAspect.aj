package at.dallermassl.ap.security.taint.trace;

import org.aspectj.lang.JoinPoint;

public abstract aspect AbstractIndentedLoggingAspect {

    /**
     * The current number of indentation levels.
     */
    protected int indentationlevel = 0;

    /**
     * Override and provide pointcut to log.
     */
    protected abstract pointcut loggingOperations();

    /**
     * Override and provide the actual logging statement for when the logged
     * method is entered.
     *
     * @param indent
     *            The string of spaces that provides the current indentation.
     * @param joinPoint
     *            Information about the current joinpoint.
     */
    protected abstract void beforeLog(int level, JoinPoint joinPoint);

    /**
     * Override and provide the actual logging statement for when the logged
     * method is exited.
     *
     * @param indent
     *            The string of spaces that provides the current indentation.
     * @param joinPoint
     *            Information about the current joinpoint.
     */
    protected abstract void afterLog(int level, JoinPoint joinPoint, Object result);

    /**
     * The aspect itself wrapping around all methods.
     * @return the object returned by the instrumented method.
     */
    Object around(): loggingOperations() {
        indentationlevel++;
        beforeLog(indentationlevel, thisJoinPoint);
        Object result = null;
        try {
            result = proceed();
        } finally {
            afterLog(indentationlevel, thisJoinPoint, result);
            indentationlevel--;
        }
        return result;
    }
}


