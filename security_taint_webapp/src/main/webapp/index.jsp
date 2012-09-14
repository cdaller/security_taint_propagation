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
        user = Sanitizer.sanitize(request.getParameter("user"));
        pass = Sanitizer.sanitize(request.getParameter("pass"));
        
        out.println("user=" + user);
        out.println("pass=" + pass);
        %>
        <ul>
          <li>User: <%=user%></li>
          <li>Password: <%=pass%></li>
        </ul>
        
    </body>
</html>
