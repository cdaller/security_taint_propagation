/**
 *
 */
package at.dallermassl.ap.security.test.taint.composition;

import org.junit.Test;

import at.dallermassl.ap.security.taint.composition.CompositionManager;

/**
 * @author christof.dallermassl
 *
 */
public class CompositionManagerTest {


    @Test
    public void testSimple() {
        String foo = "foo";
        foo.setTainted(true);
        System.out.println(CompositionManager.getInstance().getCompositionString(foo));
    }


    @Test
    public void testConcat() {
        String foo = "foo";
        foo.setTainted(true);

        String foobar = foo.concat("bar");
        String baz = foobar.concat(foobar);
        System.out.println(CompositionManager.getInstance().getCompositionString(baz));

        String bazoo = baz.concat("blabla");
        bazoo = bazoo.substring(0,5);
        System.out.println(CompositionManager.getInstance().getCompositionString(bazoo));

        /*
        "foobarfoobar" (3 baz)
          "foobar" (2 foobar)
            "foo" (1 foo)
            concat Zeile 1
            "bar" (0)
          concat Zeile 2
          "foobar" (2 foobar)
            "foo" (1 foo)
            concat Zeile 1
            "bar" (0)
         */

    }


}
