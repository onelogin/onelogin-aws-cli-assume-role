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

Client olClient = new Client();
olClient.getAccessToken();

String stateToken = request.getParameter("state_token");
String appId = request.getParameter("app_id");
String otpToken = request.getParameter("otp_token");
String deviceId = request.getParameter("device");

String samlResponse = null;
SAMLEndpointResponse samlEndpointResponseAfterVerify = olClient.getSAMLAssertionVerifying(appId, deviceId, stateToken, otpToken, null);

String status = samlEndpointResponseAfterVerify.getType();
while(status.equals("pending")) {
	TimeUnit.SECONDS.sleep(30);
	samlEndpointResponseAfterVerify = olClient.getSAMLAssertionVerifying(appId, deviceId, stateToken, otpToken, null);
	status = samlEndpointResponseAfterVerify.getType();
}
if (status.equals("success")) {
	samlResponse = samlEndpointResponseAfterVerify.getSAMLResponse();
%>
	<p>We retrieved that SAMLResponse from Onelogin that will be used in order to assume an AWS Role</p>
	<form action="select_awsrole.jsp" method="POST">
	<label>SAMLResponse</label><br>
	<textarea rows="10" cols="50" name="saml_response"><%=samlResponse %></textarea><br>
	<input type="submit" value="Continue">
	</form>
<%
}
%>
</body>
</html>