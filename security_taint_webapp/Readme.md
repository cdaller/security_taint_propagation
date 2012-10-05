# Security Taint Propagation Test Webapp

This is a simple web application that uses the taint propagation aspects.
If deployed without aspects to a tomcat, the two jsp pages just print the userinput
on the jsp page.

But if deployed with the aspect libraries in use (and the modified rt.jar) the
aspect print a message that a tainted value will be used in the jsp page.
You need a tomcat (tested with tomcat 6.0.35) and aspectj (1.7 used).

## Tomcat setup

Use the following script as $CATALINA_HOME/bin/setenv.sh (please adopt filenames and paths):
```
#!/bin/bash
CATALINA_OPTS="$CATALINA_OPTS -Xbootclasspath/p:..//security_taint_extension/target/tainted-rt-1.6.jar"
CATALINA_OPTS="$CATALINA_OPTS -javaagent:$HOME/java/aspectj1.7/lib/aspectjweaver.jar"
export CATALINA_OPTS
CLASSPATH="$CLASSPATH:$HOME/java/aspectj1.7/lib/aspectjrt.jar"
CLASSPATH="$CLASSPATH:../security_taint_propagation/target/security.taint.propagation-0.0.2-SNAPSHOT.jar"
CLASSPATH="$CLASSPATH:../security_taint_propagation_http/target/security.taint.propagation.http-0.0.2-SNAPSHOT.jar"
export CLASSPATH
echo "setenv.sh was read"
echo "CATALINA_OPTS:$CATALINA_OPTS"
echo "CLASSPATH:$CLASSPATH"
```

## Maven Jetty-Plugin setup

You can use the configured jetty plugin to start the webapp. BUT you need to instrument
the application server. Unfortunately this is not possible within maven, but needs to
be setup on startup:

### Linux
Use the following 'start_jetty_with_aspects.sh' script:
```
export MAVEN_OPTS="-Xbootclasspath/p:../security_taint_extension/target/tainted-rt-1.6.jar -javaagent:$HOME/.m2/repository/org/aspectj/aspectjweaver/1.7.0/aspectjweaver-1.7.0.jar"
echo "Using the following params: $MAVEN_OPTS"
mvn jetty:run
```
It sets the modified rt.jar (for extending java.lang.String) as bootclasspath
and adds the runtime weaver from aspectj as javaagent. The rest of the classpath
is set up in maven's pom.xml.

## Result
The aspects are configured to print a message as soon as a tainted resource reaches
a defined sink. So when you start the application, open the browser at
http://localhost:8080/security.taint.webapp and enter some values in the input fields,
you'll see the following messages on the console:
```
....
[INFO] Started Jetty Server
[INFO] Starting scanner at interval of 10 seconds.
SECURITY-TAINT-WARNING: Tainted value will be used in a sink![ sink code: org.apache.jsp.index_jsp:111/call(JspWriter.print(..)),tainted sources: Http Servlet Request Parameter, value: 'test']
SECURITY-TAINT-WARNING: Tainted value will be used in a sink![ sink code: org.apache.jsp.index_jsp:114/call(JspWriter.print(..)),tainted sources: Http Servlet Request Parameter, value: 'tests']
SECURITY-TAINT-WARNING: Tainted value will be used in a sink![ sink code: org.apache.jsp.index_jsp:130/call(JspWriter.print(..)),tainted sources: Http Servlet Request Parameter, value: 'test']
SECURITY-TAINT-WARNING: Tainted value will be used in a sink![ sink code: org.apache.jsp.index_jsp:133/call(JspWriter.print(..)),tainted sources: Http Servlet Request Parameter, value: 'tests']
SECURITY-TAINT-WARNING: Tainted value will be used in a sink![ sink code: org.apache.jsp.index_jsp:140/call(JspWriter.println(..)),tainted sources: Http Servlet Request Parameter, value: '<li>User: test</li>']
SECURITY-TAINT-WARNING: Tainted value will be used in a sink![ sink code: org.apache.jsp.index_jsp:141/call(JspWriter.println(..)),tainted sources: Http Servlet Request Parameter, value: '<li>Password: tests</li>']
```
This gives feedback that in the compile class for "index.jsp" a http request parameter was
printed into the html response without sanitation. In this case this indicates that
the given page is vulnerable to cross site scripting (XSS) as not html input was escaped.

When you check the "Sanitize input on server" the sanitizer class is used to sanitize
the user input and the tainted warnings do not appear.

Try to use the following input and see what happens:
```
test<script>alert("xss");</script>test2
```
Please note that new latest safari is able to detect this kind of XSS and prevents
javascript execution. Firefox will work though.
