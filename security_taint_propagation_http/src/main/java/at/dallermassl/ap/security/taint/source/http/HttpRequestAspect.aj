/**
 * 
 */
package at.dallermassl.ap.security.taint.source.http;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import javax.servlet.ServletRequest;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;

/**
 * @author cdaller
 * TODO: Source: System.getenv(), Db-Statements, File Reads, ...
 */
public aspect HttpRequestAspect {
    // ServletRequest
    after() returning (String returnObject): call(public String ServletRequest.getParameter(String)) {
        System.out.println(thisJoinPoint.getSignature());
        if (returnObject != null) {
            returnObject.setTainted(true);
        }
    }

    after() returning (String[] returnObject): call(public String[] ServletRequest.getParameterValues(String)) {
        if (returnObject != null) {
            for(String value : returnObject) {
                value.setTainted(true);
            }
        }
    }
    
    Map<String, String[]> around(ServletRequest original): call(public String[] ServletRequest.getParameterMap()) && target(original) {
        Map<String, String[]> paramMap = original.getParameterMap(); 
        Map<String, String[]> taintedMap = null;
        
        String key;
        String[] values;
        if (paramMap != null) {
            taintedMap = new HashMap<String, String[]>();
            for (Entry<String, String[]> entry : paramMap.entrySet()) {
                key = entry.getKey();
                values = entry.getValue();
                for (String value : values) {
                    value.setTainted(true);
                }
                taintedMap.put(key, values);
            } 
        }
        return taintedMap;
    }

    Enumeration<String> around(ServletRequest original): call(public String[] ServletRequest.getParameterNames()) && target(original) {
        Enumeration<String> paramNames = original.getParameterNames(); 
        List<String> taintedNames = new ArrayList<String>();
        
        String value;
        while(paramNames.hasMoreElements()) {
           value = paramNames.nextElement();
           value.setTainted(true);
           taintedNames.add(value);
        }
        return Collections.enumeration(taintedNames);
    }

    // HttpServletRequest
    after() returning (String returnObject): call(public String HttpServletRequest.getContextPath()) {
        returnObject.setTainted(true);
    }
    
    after() returning (String returnObject): call(public String HttpServletRequest.getHeader(String)) {
        returnObject.setTainted(true);
    }    

    Enumeration<String> around(HttpServletRequest original): call(public String[] HttpServletRequest.getHeaderNames()) && target(original) {
        Enumeration<String> paramNames = original.getHeaderNames(); 
        List<String> taintedNames = new ArrayList<String>();
        
        String value;
        while(paramNames.hasMoreElements()) {
           value = paramNames.nextElement();
           value.setTainted(true);
           taintedNames.add(value);
        }
        return Collections.enumeration(taintedNames);
    }

    Enumeration<String> around(HttpServletRequest original, String name): call(public String[] HttpServletRequest.getHeaders(String)) && target(original) && args(name) {
        Enumeration<String> paramNames = original.getHeaders(name); 
        List<String> taintedNames = new ArrayList<String>();
        
        String value;
        while(paramNames.hasMoreElements()) {
           value = paramNames.nextElement();
           value.setTainted(true);
           taintedNames.add(value);
        }
        return Collections.enumeration(taintedNames);
    }

    after() returning (String returnObject): call(public String HttpServletRequest.getPathInfo()) {
        if (returnObject != null) {
            returnObject.setTainted(true);
        }
    }

    after() returning (String returnObject): call(public String HttpServletRequest.getPathTranslated()) {
        if (returnObject != null) {
            returnObject.setTainted(true);
        }
    }    

    after() returning (String returnObject): call(public String HttpServletRequest.getQueryString()) {
        if (returnObject != null) {
            returnObject.setTainted(true);
        }
    }    

    after() returning (String returnObject): call(public String HttpServletRequest.getRequestURI()) {
        if (returnObject != null) {
            returnObject.setTainted(true);
        }
    }

    after() returning (StringBuffer returnObject): call(public String HttpServletRequest.getRequestURL()) {
        if (returnObject != null) {
            returnObject.setTainted(true);
        }
    }

    after() returning (String returnObject): call(public String HttpServletRequest.getServletPath()) {
        if (returnObject != null) {
            returnObject.setTainted(true);
        }
    }


    // cookie
    after() returning (String returnObject): call(public String Cookie.getComment()) {
        if (returnObject != null) {
            returnObject.setTainted(true);        
        }
    }

    after() returning (String returnObject): call(public String Cookie.getDomain()) {
        if (returnObject != null) {
            returnObject.setTainted(true);        
        }
    }

    after() returning (String returnObject): call(public String Cookie.getName()) {
        if (returnObject != null) {
            returnObject.setTainted(true);        
        }
    }

    after() returning (String returnObject): call(public String Cookie.getPath()) {
        if (returnObject != null) {
            returnObject.setTainted(true);        
        }
    }

    after() returning (String returnObject): call(public String Cookie.getValue()) {
        if (returnObject != null) {
            returnObject.setTainted(true);
        }
    }


}
