/**
 * 
 */
package at.dallermassl.ap.security.taint.sink.sql;

import java.sql.Connection;
import java.sql.Statement;

import at.dallermassl.ap.security.taint.sink.AbstractTaintedSinkAspect;

/**
 * Source Aspects for java.sql classes.
 * 
 * @author cdaller
 */
public aspect JdbcSinkAspect extends AbstractTaintedSinkAspect {
    
    public JdbcSinkAspect() {
        super("SQL-Injection");
    }
    
    before(String value): args(value, ..) && (
                    call(public * Statement.execute*(String, ..)) ||
                    call(public * Statement.execute*(String, ..)) ||
                    call(public * Statement.execute*(String, ..)) ||
                    call(public * Statement.addBatch(String))
                    ) {
        if (value != null && value.isTainted()) {
            handleTaintedSink(thisJoinPoint, value);
        }
    }
        
    // PreparedStatement
    before(String value): call(public * Connection.prepareStatement(String, ..)) && args(value, ..) {
        if (value != null && value.isTainted()) {
            handleTaintedSink(thisJoinPoint, value);
        }
    }
}
