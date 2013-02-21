/**
 * 
 */
package at.dallermassl.ap.security.taint.extension;



/**
 * Adds the TaintedObject interface/implementation to java.lang.String and similar classes.
 * @author cdaller
 *
 */
public aspect TaintedObjectAspect extends AbstractTaintedObjectAspect {
    
    declare parents: java.lang.String implements TaintedObject;
    declare parents: java.lang.StringBuffer implements TaintedObject;
    declare parents: java.lang.StringBuilder implements TaintedObject;    
    declare parents: org.apache.commons.lang.text.StrBuilder implements TaintedObject;    

}
