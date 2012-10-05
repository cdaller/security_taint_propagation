#!/bin/sh
export MAVEN_OPTS="-Xbootclasspath/p:../security_taint_extension/target/tainted-rt-1.6.jar -javaagent:$HOME/.m2/repository/org/aspectj/aspectjweaver/1.7.0/aspectjweaver-1.7.0.jar"
echo "Using the following params: $MAVEN_OPTS"
mvn jetty:run
