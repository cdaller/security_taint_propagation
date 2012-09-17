/**
 * 
 */
package at.dallermassl.ap.security.taint.sink.io;

import java.io.File;
import java.io.IOException;
import java.io.PrintWriter;

import junit.framework.Assert;

import org.junit.Test;

import at.dallermassl.ap.security.taint.source.TaintedSourceInfo;

/**
 * @author cdaller
 *
 */
public class PrintWriterSinkTest {

    @Test
    public void testPrintString() throws IOException {
        
        boolean blockTainted = PrintWriterAspect.isBlockTainted();
        PrintWriterAspect.setBlockTainted(true);
        int taintSourceId = TaintedSourceInfo.addSourceInfo("PrintWriterSinkTest");

        try {
            String foo = "foo";
            foo.setTainted(true);
            foo.addTaintedSourceId(taintSourceId);
            //System.out.println("printing tainted:");
            PrintWriter writer = new PrintWriter(File.createTempFile("aspecttest", ".tmp"));
            try {
                writer.print(foo);
                Assert.fail("must throw a SecurityException");
            } catch (SecurityException e) {
                Assert.assertTrue("Security exception was thrown " + e.getMessage(), true);
            }
            Assert.assertTrue("print does not change taintedness", foo.isTainted());
            
            try {
                writer.println(foo);
                Assert.fail("must throw a SecurityException");
            } catch (SecurityException e) {
                Assert.assertTrue("Security exception was thrown", true);
            }
            writer.flush();
            Assert.assertTrue("print does not change taintedness", foo.isTainted());

            foo.setTainted(false);
            writer.print(foo);
            writer.println(foo);
            writer.flush();
        } finally {
            PrintWriterAspect.setBlockTainted(blockTainted);
        }
    }

}
