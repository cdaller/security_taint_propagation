#!/bin/bash
if [ -z "$ASPECTJ_HOME" ]; then
  ASPECTJ_HOME=$HOME/java/aspectj1.7
fi
echo "ASPECTJ_HOME=$ASPECTJ_HOME"

# export JAVA_HOME=`/usr/libexec/java_home --version 1.7`
# echo "JAVA_HOME=$JAVA_HOME"
# $ASPECTJ_HOME/bin/ajc \
#       -classpath $ASPECTJ_HOME/lib/aspectjrt.jar \
#       -inpath $JAVA_HOME/jre/lib/rt.jar \
#       -outjar tainted-rt-1.7.jar \
#       -1.7 \
#       src/main/java/com/unycom/ap/security/taint/extension/java/lang/*.aj
#
# echo "created tainted-rt-1.7.jar for jdk 1.7"

export JAVA_HOME=`/usr/libexec/java_home --version 1.6`
echo "JAVA_HOME=$JAVA_HOME"
$ASPECTJ_HOME/bin/ajc \
      -classpath $ASPECTJ_HOME/lib/aspectjrt.jar \
      -inpath $JAVA_HOME/../Classes/classes.jar \
      -outjar tainted-rt-1.6.jar \
      -1.6 \
      src/main/java/com/unycom/ap/security/taint/extension/java/lang/*.aj

echo "created tainted-rt-1.6.jar for jdk 1.6"
