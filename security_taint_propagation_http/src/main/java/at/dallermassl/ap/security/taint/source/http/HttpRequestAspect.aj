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
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.Cookie;

import at.dallermassl.ap.security.taint.source.AbstractTaintedSourceAspect;
import at.dallermassl.ap.security.taint.source.TaintedSourceInfo;

/**
 * @author cdaller
 * TODO: Source: System.getenv(), Db-Statements, File Reads, ...
 */
public aspect HttpRequestAspect extends AbstractTaintedSourceAspect {
    
    private int HTTP_PARAMETER_SOURCE_ID = TaintedSourceInfo.addSourceInfo("Http Servlet Request Parameter");
    private int HTTP_COOKIE_SOURCE_ID = TaintedSourceInfo.addSourceInfo("Http Servlet Request Cookie");
    private int HTTP_HEADER_SOURCE_ID = TaintedSourceInfo.addSourceInfo("Http Servlet Request Header");
    private int HTTP_URL_SOURCE_ID = TaintedSourceInfo.addSourceInfo("Http Servlet Request Url");
    
    // ServletRequest
    after() returning (String returnObject): call(public String ServletRequest.getParameter(String)) {
//        System.out.println(thisJoinPoint.getSignature());
        if (returnObject != null) {
            returnObject.setTainted(true);
            returnObject.addTaintedSourceId(HTTP_PARAMETER_SOURCE_ID);
        }
        postProcessTaintedSource(thisJoinPoint, returnObject);
    }

    after() returning (String[] returnObject): call(public String[] ServletRequest.getParameterValues(String)) {
        if (returnObject != null) {
            for(String value : returnObject) {
                value.setTainted(true);
                value.addTaintedSourceId(HTTP_PARAMETER_SOURCE_ID);
                postProcessTaintedSource(thisJoinPoint, value);
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
                    value.addTaintedSourceId(HTTP_PARAMETER_SOURCE_ID);
                    postProcessTaintedSource(thisJoinPoint, value);
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
           value.addTaintedSourceId(HTTP_PARAMETER_SOURCE_ID);
           postProcessTaintedSource(thisJoinPoint, value);
           taintedNames.add(value);
        }
        return Collections.enumeration(taintedNames);
    }

    // HttpServletRequest
//    after() returning (String returnObject): call(public String HttpServletRequest.getContextPath()) {
//        if (returnObject != null) {
//            returnObject.setTainted(true);
//            returnObject.addTaintedSourceId(HTTP_URL_SOURCE_ID);
//        }
//    }
    
    after() returning (String returnObject): call(public String HttpServletRequest.getHeader(String)) {
        if (returnObject != null) {
            returnObject.setTainted(true);
            returnObject.addTaintedSourceId(HTTP_HEADER_SOURCE_ID);
        }
        postProcessTaintedSource(thisJoinPoint, returnObject);
    }    

    Enumeration<String> around(HttpServletRequest original): call(public String[] HttpServletRequest.getHeaderNames()) && target(original) {
        Enumeration<String> paramNames = original.getHeaderNames(); 
        List<String> taintedNames = new ArrayList<String>();
        
        String value;
        while(paramNames.hasMoreElements()) {
           value = paramNames.nextElement();
           value.setTainted(true);
           value.addTaintedSourceId(HTTP_HEADER_SOURCE_ID);
           postProcessTaintedSource(thisJoinPoint, value);
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
           value.addTaintedSourceId(HTTP_HEADER_SOURCE_ID);
           postProcessTaintedSource(thisJoinPoint, value);
           taintedNames.add(value);
        }
        return Collections.enumeration(taintedNames);
    }


    after() returning (String returnObject): 
        call(public String HttpServletRequest.getServletPath()) ||
        call(public String HttpServletRequest.getRequestURL()) ||
        call(public String HttpServletRequest.getRequestURI()) ||
        call(public String HttpServletRequest.getQueryString()) ||
        call(public String HttpServletRequest.getPathTranslated()) ||
        call(public String HttpServletRequest.getPathInfo()) {
        if (returnObject != null) {
            returnObject.setTainted(true);
            returnObject.addTaintedSourceId(HTTP_URL_SOURCE_ID);
        }
        postProcessTaintedSource(thisJoinPoint, returnObject);
    }
    
    // cookie
    after() returning (String returnObject): 
        call(public String Cookie.getValue()) ||
        call(public String Cookie.getPath()) ||
        call(public String Cookie.getName()) ||
        call(public String Cookie.getDomain()) ||
        call(public String Cookie.getComment()) {
        if (returnObject != null) {
            returnObject.setTainted(true);
            returnObject.addTaintedSourceId(HTTP_COOKIE_SOURCE_ID);
        }
        postProcessTaintedSource(thisJoinPoint, returnObject);
    }

}
