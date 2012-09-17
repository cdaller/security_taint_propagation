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
        <h1>Safe parameters - sanitation is done!</h1>

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
        
        <form name="input" action="./" method="get">
          <input type="text" name="username" value="<%=user%>"/><br/>
          <input type="text" name="password" value="<%=pass%>"/><br/>
          <input type="radio" name="sanitize" value="true" <%=checkedString%>/> Sanitize input on server<br/>
          <input type="radio" name="sanitize" value="false"  <%=notCheckedString%>/> Do not sanitize input on server<br/>
          <input type="submit" value="Submit"/>
        </form>

        List of parameters:
        <ul>
          <li>User: <%=user%></li>
          <li>Password: <%=pass%></li>
        </ul>
        
        List of parameters printed directly to PrintWriter
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
