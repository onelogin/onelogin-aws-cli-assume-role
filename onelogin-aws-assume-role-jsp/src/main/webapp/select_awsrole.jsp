<%@page import="java.util.concurrent.TimeUnit"%>
<%@page import="java.util.List"%>
<%@page import="java.util.HashMap"%>
<%@page import="com.onelogin.saml2.authn.SamlResponse"%>
<%@page import="com.onelogin.saml2.http.HttpRequest"%>

<%@page language="java" contentType="text/html; charset=UTF-8"
	pageEncoding="UTF-8"%>
<!DOCTYPE html>
<html>
<head>
	 <meta charset="utf-8">
	 <meta http-equiv="X-UA-Compatible" content="IE=edge">
     <meta name="viewport" content="width=device-width, initial-scale=1">
	 <title>A JSP to test the use of AWS Assume Role</title>
</head>
<body>
<%

String samlResponse = request.getParameter("saml_response");

HttpRequest simulatedRequest = new HttpRequest("http://example.com");
simulatedRequest = simulatedRequest.addParameter("SAMLResponse", samlResponse);

SamlResponse samlResponseObj = new SamlResponse(null, simulatedRequest);
HashMap<String, List<String>> attributes = samlResponseObj.getAttributes();
if (!attributes.containsKey("https://aws.amazon.com/SAML/Attributes/Role")) {
%>
	<p>SAMLResponse from Identity Provider does not contain AWS Role info</p>
<%
} else {
	String selectedRole;
	List<String> roleData = attributes.get("https://aws.amazon.com/SAML/Attributes/Role");
	if (roleData.size() > 0) {
%>
	<form action="credentials.jsp" method="POST">
<%
	if (roleData.size() == 1 && !roleData.get(0).isEmpty()) {
		String roleDataStr = roleData.get(0);
		String[] roleInfo = roleDataStr.split(":");
		String accountId = roleInfo[4];
		String roleName = roleInfo[5].replace("role/", "");
		String name = roleName + "(Account " + accountId + ")";
		out.print("<span>Selected Role: " + name + "</span></br>");
		out.print("<input type=\"hidden\" name=\"aws_role\" value=\"" + roleDataStr + "\"\">");
	} else {

%>
		<label>Available Roles...</label>
		<select name="aws_role">
<%
		for (int i = 0; i < roleData.size(); i++) {
			String roleDataStr = roleData.get(i);
			String[] roleInfo = roleDataStr.split(":");
			String accountId = roleInfo[4];
			String roleName = roleInfo[5].replace("role/", "");
			String name = roleName + "(Account " + accountId + ")";
			out.print("<option value=\""+roleDataStr+"\">"+name+"</option>");
		}
%>
		</select><br>
<%
	}
%>
      <label>AWS Region (Ex: us-east-1): </label>
	  <input type="text" name="aws_region">
	  <input type="hidden" name="saml_response" value="<%=samlResponse %>"><br>
	  <input type="submit" value="Get AWS Credentials">
	</form>
<%
	} else {
%>
	<p>SAMLResponse from Identity Provider does not contain available AWS Role for this user</p>
<%
	}
}
%>

</body>
</html>
