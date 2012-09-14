Security Taint Extension
========================

This project creates an instrumented version of rt.jar that extends
java.lang.String with a "tainted" flag.

At the moment, I cannot create the instrumented library by the use of maven, you need
to use the shell script in this directory (see there).

You need an aspectj version downloaded somewhere to have access to ajc.
