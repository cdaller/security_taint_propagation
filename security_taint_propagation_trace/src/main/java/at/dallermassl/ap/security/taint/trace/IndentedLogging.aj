package at.dallermassl.ap.security.taint.trace;

import org.aspectj.lang.JoinPoint;

public abstract aspect IndentedLogging {

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
    protected abstract void beforeLog(String indent, JoinPoint joinPoint);

    /**
     * Override and provide the actual logging statement for when the logged
     * method is exited.
     *
     * @param indent
     *            The string of spaces that provides the current indentation.
     * @param joinPoint
     *            Information about the current joinpoint.
     */
    protected abstract void afterLog(String indent, JoinPoint joinPoint);

    Object around(): loggingOperations() {
        StringBuffer sb = new StringBuffer();
        indentationlevel++;
        for (int i = 0, spaces = indentationlevel * 2; i < spaces; i++) {
            sb.append(" ");
            beforeLog(sb.toString(), thisJoinPoint);
        }
        Object result;
        try {
            result = proceed();
        } finally {
            afterLog(sb.toString(), thisJoinPoint);
            indentationlevel--;
        }
        return result;
    }
}


