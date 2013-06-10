/**
 *
 */
package at.dallermassl.ap.security.test.taint.composition;

import junit.framework.Assert;

import org.junit.Before;
import org.junit.Test;

import at.dallermassl.ap.security.taint.Configuration;
import at.dallermassl.ap.security.taint.composition.CompositionManager;
import at.dallermassl.ap.security.taint.composition.CompositionTreeNode;
import at.dallermassl.ap.security.taint.extension.TaintedObject;

/**
 * @author christof.dallermassl
 *
 */
public class CompositionManagerTest {
    CompositionManager manager;

    @Before
    public void initCompositionManager() {
        if (manager == null) {
            manager = CompositionManager.getInstance();
            Configuration.setTaintCompositionEnabled(true);
        } else {
            manager.clear();
        }

    }


    private void checkComposition(TaintedObject composite, String ... directComponents) {
        if (!Configuration.isTaintCompositionEnabled()) {
            Assert.fail("taint composition is not enabled!");
        }
        // test composite:
        CompositionTreeNode node = manager.getNode(composite);
        Assert.assertNotNull(node);
        Assert.assertEquals(composite, node.getComponentValue());
        Assert.assertEquals(composite.getTaintedObjectId(), node.getObjectId());
        Assert.assertEquals(composite.isTainted(), node.getObjectId() > 0);

        // test components:
        if (directComponents != null) { // prevent self reference infinite loops
            Assert.assertEquals(directComponents.length, node.getComposites().size());
            for (String component : directComponents) {
                checkComposition(component, (String[]) null);
            }
        }
    }

    @Test
    public void testNodeCreation() {
        if (!Configuration.isTaintCompositionEnabled()) {
            Assert.fail("taint composition is not enabled!");
        }
        String foo = "foo";
        foo.setTainted(true);

        //System.out.println(CompositionManager.getInstance().getCompositionString(foo));
        checkComposition(foo, (String[]) null);
    }

    @Test
    public void testNodeConstructor() {
        if (!Configuration.isTaintCompositionEnabled()) {
            Assert.fail("taint composition is not enabled!");
        }
        String foo = "foo";
        foo.setTainted(true);

        String bar = new String(foo);

        //System.out.println(manager.getCompositionString(bar));
        checkComposition(bar, foo);
    }



    @Test
    public void testStringConcat() {
        if (!Configuration.isTaintCompositionEnabled()) {
            Assert.fail("taint composition is not enabled!");
        }
        String foo = "foo";
        foo.setTainted(true);

        String foobar = foo.concat("bar");

        //System.out.println(manager.getCompositionString(foobar));
        checkComposition(foobar, foo, "bar");

        String baz = foobar.concat(foobar);

        //System.out.println(CompositionManager.getInstance().getCompositionString(baz));
        checkComposition(foobar, foobar, foobar);

    }

    @Test
    public void testStringSubstring() {
        if (!Configuration.isTaintCompositionEnabled()) {
            Assert.fail("taint composition is not enabled!");
        }
        String foobar = "foobar";
        foobar.setTainted(true);
        String foo = foobar.substring(0, 3);

        //System.out.println(CompositionManager.getInstance().getCompositionString(foo));
        checkComposition(foo, foobar);
    }

    @Test
    public void testStringSequence() {
        if (!Configuration.isTaintCompositionEnabled()) {
            Assert.fail("taint composition is not enabled!");
        }
        String foobar = "foobar";
        foobar.setTainted(true);
        CharSequence foo = foobar.subSequence(0, 3);

        //System.out.println(CompositionManager.getInstance().getCompositionString((TaintedObject) foo));
        checkComposition((TaintedObject) foo, foobar);
    }

    @Test
    public void testStringSplit() {
        if (!Configuration.isTaintCompositionEnabled()) {
            Assert.fail("taint composition is not enabled!");
        }
        String foobar = "foo,bar,baz";
        foobar.setTainted(true);
        String[] split = foobar.split(",");
        Assert.assertEquals(3,  split.length);
        Assert.assertEquals("foo", split[0]);
        Assert.assertEquals("bar", split[1]);
        Assert.assertEquals("baz", split[2]);

        //System.out.println(CompositionManager.getInstance().getCompositionString(split[0]));
        checkComposition(split[0], foobar);
        //System.out.println(CompositionManager.getInstance().getCompositionString(split[1]));
        checkComposition(split[1], foobar);
        //System.out.println(CompositionManager.getInstance().getCompositionString(split[2]));
        checkComposition(split[2], foobar);
    }




}
