# Security Taint Propagation Test Webapp

This is a simple web application that uses the taint propagation aspects.
If deployed without aspects to a tomcat, the two jsp pages just print the userinput
on the jsp page.

But if deployed with the aspect libraries in use (and the modified java runtime rt.jar) the
aspect print a message that a tainted value will be used in the jsp page.
Maven configuration allows a quick start with ```mvn jetty:run-forked``` in this project.
Please do not forget to ```mvn install``` the main project first as otherwise the dependencies 
are not found!

## Tomcat setup

Use the following script as $CATALINA_HOME/bin/setenv.sh (please adopt filenames and paths):
```
rem setenv.bat: adding taint propagation to tomcat: 

set BASE_DIR=<path_to_this_directory>/security_taint_propagation
set MAVEN_REPO=F:/work/m2repo
set ASPECTJ_VERSION=1.8.8

set JAVA_OPTS=-Xbootclasspath/p:%BASE_DIR%/security_taint_extension/target/tainted-rt-1.8.jar %JAVA_OPTS%
set JAVA_OPTS=-javaagent:%MAVEN_REPO%/org/aspectj/aspectjweaver/%ASPECTJ_VERSION%/aspectjweaver-%ASPECTJ_VERSION%.jar %JAVA_OPTS%

set JAVA_OPTS=-Xms256m -Xmx1800M -XX:MaxPermSize=256m %JAVA_OPTS%

set JAVA_ENDORSED_DIRS=%MAVEN_REPO%/org/aspectj/aspectjrt/%ASPECTJ_VERSION%/;%JAVA_ENDORSED_DIRS%
set JAVA_ENDORSED_DIRS=%BASE_DIR%/security_taint_propagation_http/target/;%JAVA_ENDORSED_DIRS%
set JAVA_ENDORSED_DIRS=%BASE_DIR%/security_taint_propagation/target/;%JAVA_ENDORSED_DIRS%
```

## Maven Jetty-Plugin setup

You can use the configured jetty plugin to start the webapp by calling ```mvn jetty:run-forked```.

It sets the modified rt.jar (for extending java.lang.String) as bootclasspath
and adds the runtime weaver from aspectj as javaagent. The rest of the classpath
is set up in maven's pom.xml.

## Result
The aspects are configured to print a message as soon as a tainted resource reaches
a defined sink. So when you start the application, open the browser at
http://localhost:8080/taintwebapp and enter some values in the input fields,
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
