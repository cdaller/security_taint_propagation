security_taint_propagation
==========================

This project defines some java aspects that allow to follow tainted strings from a
source to a sink to find security leaks in software (SQL-Injection, Cross-Site-Scripting (XSS)).

Therefore the java.lang.String class is extended with a "tainted" flag. This flag is
set on all strings that come from defined sources (e.g. HttpServletRequest.getParameter())
and passed to all strings that use the tainted string (e.g. String foo = "foo" + tainted;
results in tainted foo). When a tainted string reaches a sink, the system can react in
different ways (log message, throw exception, ...).

Some "cleaner" or "sanitizer" methods can be used to remove the tainted flag. E.g. when
you want to protect your application from XSS, a cleaner method would escape all
characters that may be interpreted by the browser (especially the "<" sign).

_Note_:
This project is in a early stage, do not expect an easy to use pluginable thing you
can use without deeper knowledge!

Everyone is welcome to improve this project.

There are multiple parts in this project
----------------------------------------
* security_taint_extension: contains aspects that extend java.lang.String (add property
  "tainted"). Therefore you need to weave the new aspect into the jdk's rt.jar (on OSX's
  1.6 jdk it is named classes.jar) and create a new "tainted-rt.jar". This new jar is
  used in the bootclasspath of all projects that use the aspects (and the application
  itself as well!).
* security_taint_propagation: holds aspects that propagate the tainted flag from
  String to StringBuffer and StringBuilder objects (e.g. copy a tainted String into
  a StringBuilder, the new StringBuilder has to be flagged as tainted as well).
  Additionally it holds some definitions of sinks and sources.
* security_taint_propagation_http: holds sources for web applications
* security_taint_webapp: very simple example webapp that demonstrates sources, sinks
  and sanitation of tainted strings.
