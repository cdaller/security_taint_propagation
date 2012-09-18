/**
 * 
 */
package at.dallermassl.ap.security.taint.source.sql;

import java.sql.ResultSet;

import at.dallermassl.ap.security.taint.source.TaintedSourceInfo;

/**
 * @author cdaller
 * TODO: Source: System.getenv(), File Reads, ...
 */
public aspect JdbcSourceAspect {
    
    private int JDBC_RESULTSET_SOURCE_ID = TaintedSourceInfo.addSourceInfo("JDBC Sql Result Set");    
    
    after() returning (String returnObject): 
        call(public String ResultSet.getNString(..)) ||
        call(public String ResultSet.getString(..)) {
        if (returnObject != null) {
            returnObject.setTainted(true);
            returnObject.addTaintedSourceId(JDBC_RESULTSET_SOURCE_ID);
        }
    }


}
