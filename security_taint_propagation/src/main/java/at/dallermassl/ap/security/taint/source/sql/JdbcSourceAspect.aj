/**
 * 
 */
package at.dallermassl.ap.security.taint.source.sql;

import java.sql.ResultSet;

import at.dallermassl.ap.security.taint.source.TaintedSourceInfo;

/**
 * @author cdaller
 * TODO: Source: System.getenv(), Db-Statements, File Reads, ...
 */
public aspect JdbcSourceAspect {
    
    private int JDBC_RESULTSET_SOURCE_ID = TaintedSourceInfo.addSourceInfo("JDBC Sql Result Set");    
    
    after() returning (String returnObject): 
        call(public String ResultSet.getNString(String)) ||
        call(public String ResultSet.getNString(int)) ||
        call(public String ResultSet.getString(String)) ||
        call(public String ResultSet.getString(int)) {
        if (returnObject != null) {
            returnObject.setTainted(true);
            returnObject.addTaintedSourceId(JDBC_RESULTSET_SOURCE_ID);
        }
    }


}
