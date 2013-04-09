# Dynamic Security Taint Propagation in Java via Java Aspects

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

Christof Dallermassl (christof at dallermassl dot at)

## Background knowledge

I found two papers about this topic:
* [Vivek Haldar, Deepak Chandra, Michael Franz: Dynamic Taint Propagation for Java](http://www.acsac.org/2005/papers/45.pdf)
* [A presentation at blackhat security conference](http://www.blackhat.com/presentations/bh-dc-08/Chess-West/Presentation/bh-dc-08-chess-west.pdf)

## Note
This project is in a early stage (but works!), do not expect an easy to use plugable thing you
can use without deeper knowledge!

Everyone is welcome to help to improve this project.


## There are multiple parts in this project
* **security_taint_extension**: contains aspects that extend java.lang.String (add property
  "tainted"). Therefore you need to weave the new aspect into the jdk's rt.jar (on OSX's
  1.6 jdk it is named classes.jar) and create a new "tainted-rt.jar". This new jar is
  used in the bootclasspath of all projects that use the aspects (and the application
  itself as well!).
* **security_taint_propagation**: holds aspects that propagate the tainted flag from
  String to StringBuffer and StringBuilder objects (e.g. copy a tainted String into
  a StringBuilder, the new StringBuilder has to be flagged as tainted as well).
  Additionally it holds some definitions of sinks and sources.
* **security_taint_propagation_http**: holds taint sources and sinks for web applications
* **security_taint_webapp**: very simple example webapp that demonstrates sources, sinks
  and sanitation of tainted strings. It needs to be deployed to an instrumented tomcat
  server to work as expected (see Readme.md in the project).

## Eclipse setup
The projects can be used as maven nature projects. Beware that the tainted-rt-1.x.jar
always comes before the system lib (jre lib) as otherwise the java.lang.String modification
will not be found! Use the projects properties, "Java Build Path"/"Order and Export" to put the
"JRE System Library" to the bottom. This needs to be done every time after "Maven/Update Project"
was executed.

Set the default jre to 1.6 (only tested with 1.6, might work with oters JREs as well).

Do a "mvn package" first, so the modified tainted-rt-1.6.jar will be found in eclipse.

Please note that the security_taint_extension project will not build correctly in eclipse, as
it needs the modified rt.jar which it produces (hen/egg problem). In maven it works.
Use maven to package.

Add the aspect-Nature to the project: Right click on project, Configure, Convert to AspectJ Project

If you cannot start any unit tests in eclipse after modification in the aspects, remove all
Run-Configurations of the tests!

Sometimes eclipse gets confused and reports hundreds of errors:
* delete the files .classpath and .project
* in eclipse update maven nature: Maven/Update Project
* move the JRE System Library to the bottom (Properties/Java Build Path/Order and Export)
* remove AspectJ Nature and add it again

## Working with Taint Propagation

### Tomcat setup
Some libraries are needed to "arm" tomcat:
* the load time weaver of aspectj (as a java agent on startup)
* the modified String class (in tainted-rt.jar) as bootclasspath (replaces the original rt.jar from the jdk)
* the aspect that ensures that the tainted flag is propagated on string operations (security.taint.propagation...jar)
* the aspect instrumenting http sources and sinks (security.taint.propagation.http...jar)

If you want to start tomcat in eclipse with taint propagation you have to
1. create a new tomcat server named "Tomcat 6 tainted" (or similar)
2. start tomcat once (to get an entry in "Run/Debug configurations")
3. settings in "Run/Debug configurations"
  * Arguments:
-Xbootclasspath/p:D:/PATH_TO/tainted-rt-1.6.jar
-javaagent:D:/PATH_TO/aspectjweaver-1.7.1.jar
  * Classpath tab: Add the two jar files in "User Entries": security.taint.propagation-VERSION.jar, security.taint.propagation.http-VERSION.jar

### Output
The tools are configured to print a warning to system.out whenever a security leak was detected (line breaks added for better readability):
```
SECURITY-TAINT-WARNING: Tainted value will be used in a sink![ 
  type: XSS, sink code: org.apache.jsp.xxx.jsp:136/call(JspWriter.print(..)),
  tainted sources: JDBC Sql Result Set(5),
  value: '<TABLE><tr><td>Hugo von Hofmannsthal</td></tr></TABLE>'
]
```
This means that a tainted string (coming from a insecure source (user input, database)) was detected to be used in a defined sink (jsp writer, database query).

## Problems
Some problems make working with taint propagation sometimes cumbersome:
* If a jsp page is the sink (JSP Writer) only the line number in the compiled jsp servlet is printed. So the developer has to find the java code of the jsp page, find the code and then try to find the corresponding line in the jsp file. In eclipse the java classes are placed into $ECLIPSE_WORKSPACE/.metadata/.plugins/org.eclipse.wst.server.core/tmpX/work/Catalina/localhost/$WEBAPPNAME/org/apache/jsp
* The final tainted string is sometimes a concatenation of lots of parts and it is sometimes difficult to find the tainted string.
* It would be helpful to see the different tainted parts of the final string and their way through the code to detect if there really is a security leak or not.

Apart from that the tool works quite reliable.

## License
This project is licensed under [Apache 2.0](http://opensource.org/licenses/apache2.0)
