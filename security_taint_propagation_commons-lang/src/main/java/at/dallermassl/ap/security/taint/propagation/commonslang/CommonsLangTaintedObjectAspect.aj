/**
 * 
 */
package at.dallermassl.ap.security.taint.propagation.commonslang;

import at.dallermassl.ap.security.taint.extension.AbstractTaintedObjectAspect;
import at.dallermassl.ap.security.taint.extension.TaintedObject;



/**
 * Adds the TaintedObject interface/implementation to StrBuilder from commons-lang. Need load time weaving for this to work!
 * @author cdaller
 *
 */
public aspect CommonsLangTaintedObjectAspect extends AbstractTaintedObjectAspect {
   declare parents: org.apache.commons.lang.text.StrBuilder implements TaintedObject;    
}
