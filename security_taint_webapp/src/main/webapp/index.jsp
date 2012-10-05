<%@page import="at.dallermassl.ap.security.taint.webapp.Sanitizer"%>
<%@page contentType="text/html" pageEncoding="UTF-8"%>
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN"
   "http://www.w3.org/TR/html4/loose.dtd">

<html>
    <head>
        <meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
        <title>JSP Page</title>
    </head>
    <body>
        <h1>Dynamic Taint Propagation Test Page</h1>

        <%
            String user;
            String pass;
            String sanitizeString;
            boolean sanitize;
            String checkedString="";
            String notCheckedString="";

            // input params
            user = request.getParameter("username");
            pass = request.getParameter("password");
            sanitizeString = request.getParameter("sanitize");
            if (sanitizeString == null || "false".equals(sanitizeString)) {
                sanitize = false;
                notCheckedString = "checked";
            } else {
                sanitize = true;
                checkedString = "checked";
            }
            
            if (user == null) {
                user = "";
            }
            if (pass == null) {
                pass = "";
            }

            if (sanitize) {
                user = Sanitizer.sanitize(user);
                pass = Sanitizer.sanitize(pass);
            }
        %>

        <p>
        The parameters are passed to the jsp page again. The jsp page sanitizes the request
        parameters on demand (checkbox). If the web application is instrumented
        with the taint-propagation aspects and the parameters are not sanitized, the taint
        propagation sink aspects will print a warning message to the console as soon as the
        tainted strings will be printed to the jsp writer. Actually it is not important what 
        the sanitizer does. The aspects will remove the tainted flag whenever the sanitation method
        is invoked.
        </p>
        <p>
        If you cannot see anything on the console (sanitation off), the application server is
        not correctly instrumented with the aspects!
        </p>
        
        <h2>Input parameters</h2>
        <p>
        <form name="input" action="./" method="get">
          Username: <input type="text" name="username" value="<%=user%>" size="60"/><br/>
          Password: <input type="text" name="password" value="<%=pass%>" size="60"/><br/>
          <input type="radio" name="sanitize" value="true" <%=checkedString%>/> Sanitize input on server<br/>
          <input type="radio" name="sanitize" value="false"  <%=notCheckedString%>/> Do not sanitize input on server<br/>
          <input type="submit" value="Submit"/>
        </form>
        </p>

        <h2>Output parameters</h2>
        <h3>List of parameters printed with  "&lt;%= variablename %&gt;"</h3>
        <ul>
          <li>User: <%=user%></li>
          <li>Password: <%=pass%></li>
        </ul>
        <h3>List of parameters printed directly to PrintWriter "out"</h3>
        <ul>
        <%
        out.println("<li>User: " + user + "</li>");
        out.println("<li>Password: " + pass + "</li>");
        %>
        </ul>
        <!-- add image as test (was a bug) -->
        <img src="images/gear-clock_small.jpg"/>
    </body>
</html>
