Security Taint Propagation Test Webapp
======================================

This is a simple web application that uses the taint propagation aspects.
If deployed without aspects to a tomcat, the two jsp pages just print the userinput on the
jsp page.

But if deployed with the aspect libraries in use (and the modified rt.jar) the
aspect print a message that a tainted value will be used in the jsp page.

Use the following script as $CATALINA_HOME/bin/setenv.sh:
#!/bin/bash
CATALINA_OPTS="$CATALINA_OPTS -Xbootclasspath/p:$HOME/eclipse-workspace/security_taint_extension/tainted-rt-1.6.jar"
CATALINA_OPTS="$CATALINA_OPTS -javaagent:$HOME/java/aspectj1.7/lib/aspectjweaver.jar"
export CATALINA_OPTS
CLASSPATH="$CLASSPATH:$HOME/java/aspectj1.7/lib/aspectjrt.jar"
CLASSPATH="$CLASSPATH:$HOME/eclipse-workspace/security_taint_propagation/target/security.taint.propagation-0.0.2-SNAPSHOT.jar"
CLASSPATH="$CLASSPATH:$HOME/eclipse-workspace/security_taint_propagation_http/target/security.taint.propagation.http-0.0.2-SNAPSHOT.jar"
export CLASSPATH
echo "setenv.sh was read"
echo "CATALINA_OPTS:$CATALINA_OPTS"
echo "CLASSPATH:$CLASSPATH"
