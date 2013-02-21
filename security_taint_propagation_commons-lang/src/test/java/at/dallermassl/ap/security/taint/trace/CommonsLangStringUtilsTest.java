package at.dallermassl.ap.security.taint.trace;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import junit.framework.Assert;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.lang.text.StrBuilder;
import org.junit.Test;

import at.dallermassl.ap.security.taint.extension.TaintedObject;

public class CommonsLangStringUtilsTest {

    
    @Test
    public void testTaintedObject() {
        StrBuilder builder = new StrBuilder();
        Assert.assertTrue("StrBuilder is not a TaintedObject", builder instanceof TaintedObject);
    }

    @Test
    public void testTainted() {
//        StrBuilder builder = new StrBuilder();
//        Assert.assertFalse("StrBuilder is not tainted by default", builder.isTainted());   
    }

//	@Test
	public void joinTest() {
		String foo = new String("foo");
		String bar = new String("bar");
		
		foo.setTainted(true);
		List<String> list = new ArrayList<String>();
		list.add(foo);
		list.add(bar);
		Iterator<String> iterator = list.iterator();
		String result = StringUtils.join(iterator, " and ");
		Assert.assertTrue("StringUtils.join must propagate taintedness", result.isTainted());
	}
	
	
}
