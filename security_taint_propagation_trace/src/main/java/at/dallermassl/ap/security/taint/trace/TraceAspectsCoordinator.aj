package at.dallermassl.ap.security.taint.trace;

public aspect TraceAspectsCoordinator {
    declare precedence: TaintedTraceAspect, IndentationTraceAspect;
}
