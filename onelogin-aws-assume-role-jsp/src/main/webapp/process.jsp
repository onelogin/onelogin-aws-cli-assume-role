<%@page import="java.util.concurrent.TimeUnit"%>
<%@page import="java.util.List"%>

<%@page import="com.onelogin.sdk.conn.Client"%>
<%@page import="com.onelogin.sdk.model.Device"%>
<%@page import="com.onelogin.sdk.model.MFA"%>
<%@page import="com.onelogin.sdk.model.SAMLEndpointResponse"%>
<%@page import="com.onelogin.sdk.util.Settings"%>
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

String oneloginUsernameOrEmail = request.getParameter("onelogin_username_or_email");
String oneloginPassword = request.getParameter("onelogin_password");
String appId = request.getParameter("app_id");
String oneloginDomain = request.getParameter("onelogin_domain");

Client olClient = new Client();
olClient.getAccessToken();

// Get IP from onelogin.sdk.properties file, but we could also read IP from user browser.
String ip = olClient.getIP();

SAMLEndpointResponse samlEndpointResponse = olClient.getSAMLAssertion(oneloginUsernameOrEmail, oneloginPassword, appId, oneloginDomain, ip);

String status = samlEndpointResponse.getType();
while(status.equals("pending")) {
	TimeUnit.SECONDS.sleep(30);
	samlEndpointResponse = olClient.getSAMLAssertion(oneloginUsernameOrEmail, oneloginPassword, appId, oneloginDomain, ip);
	status = samlEndpointResponse.getType();
}

String samlResponse = null;
if (status.equals("success")) {
	if (samlEndpointResponse.getMFA() != null) {
		MFA mfa = samlEndpointResponse.getMFA();
		List<Device> devices = mfa.getDevices();		
%>
<form action="process_mfa.jsp" method="POST">
<label>Device: </label>
<%

 Device device;
 if (devices.size() == 1) {
		device = devices.get(0);
		out.print("<span style=\"font-style:italic;\">" + device.getType() + "</span><br>");
		out.print("<input type=\"hidden\" name=\"device\" value=\"" + device.getID() + "\"\">");	 
 } else {
%>
	<select name="device">
	<%
		for (int i=0; i < devices.size(); i++) {
			device = devices.get(i);
			out.print("<option value=\""+device.getID()+"\">"+device.getType()+"</option>");
		}
	%>
	</select><br/>
<%
 }
%>
<label>OTP Token</label><input type="text" name="otp_token" /><br/>  
<input type="hidden" name="state_token" value="<%=mfa.getStateToken() %>">
<input type="hidden" name="app_id" value="<%=appId %>">
<input type="submit" value="Submit"/>
</form>
<%
	} else {
		samlResponse = samlEndpointResponse.getSAMLResponse();
%>
	<p>We retrieved that SAMLResponse from OneLogin that will be used in order to assume an AWS Role</p>
	<form action="select_awsrole.jsp" method="POST">
	<label>SAMLResponse</label><br>
	<textarea rows="10" cols="50" name="saml_response"><%=samlResponse %></textarea><br>
	<input type="submit" value="Continue">
	</form>
<%
	}
}
%>
</body>
</html>
