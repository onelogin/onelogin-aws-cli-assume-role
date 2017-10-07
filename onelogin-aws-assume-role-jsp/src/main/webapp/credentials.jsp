<%@page import="java.util.concurrent.TimeUnit"%>
<%@page import="java.util.List"%>
<%@page import="java.util.HashMap"%>
<%@page import="java.io.InputStream"%>
<%@page import="com.onelogin.saml2.authn.SamlResponse"%>
<%@page import="com.onelogin.saml2.http.HttpRequest"%>
<%@page import="com.amazonaws.auth.AWSCredentials"%>
<%@page import="com.amazonaws.auth.AWSStaticCredentialsProvider"%>
<%@page import="com.amazonaws.auth.PropertiesCredentials"%>
<%@page import="com.amazonaws.services.securitytoken.AWSSecurityTokenService"%>
<%@page import="com.amazonaws.services.securitytoken.AWSSecurityTokenServiceClientBuilder"%>
<%@page import="com.amazonaws.services.securitytoken.model.AssumedRoleUser"%>
<%@page import="com.amazonaws.services.securitytoken.model.AssumeRoleWithSAMLResult"%>
<%@page import="com.amazonaws.services.securitytoken.model.AssumeRoleWithSAMLRequest"%>
<%@page import="com.amazonaws.services.securitytoken.model.Credentials"%>
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
String awsRole = request.getParameter("aws_role");
String awsRegion = request.getParameter("aws_region");
String samlResponse = request.getParameter("saml_response");

String[] roleData = awsRole.split(","); 
String roleArn = roleData[0];
String principalArn = roleData[1];
AssumeRoleWithSAMLRequest assumeRoleWithSAMLRequest = new AssumeRoleWithSAMLRequest()
		.withPrincipalArn(principalArn)
		.withRoleArn(roleArn)
		.withSAMLAssertion(samlResponse);

InputStream credentialStream = Thread.currentThread().getContextClassLoader().getResourceAsStream("onelogin.aws.properties");
AWSCredentials awsCredentials = new PropertiesCredentials(credentialStream);

AWSSecurityTokenServiceClientBuilder stsBuilder = AWSSecurityTokenServiceClientBuilder.standard().withCredentials(new AWSStaticCredentialsProvider(awsCredentials));
AWSSecurityTokenService stsClient = stsBuilder.withRegion(awsRegion).build();

AssumeRoleWithSAMLResult assumeRoleWithSAMLResult = stsClient.assumeRoleWithSAML(assumeRoleWithSAMLRequest);

Credentials stsCredentials = assumeRoleWithSAMLResult.getCredentials();
AssumedRoleUser assumedRoleUser = assumeRoleWithSAMLResult.getAssumedRoleUser();
%>

<label><b>AssumedRoleUser:</b></label><br><%=assumedRoleUser.getArn()%><br><br> 
<label><b>AccessKeyId:</b></label><br><%=stsCredentials.getAccessKeyId()%><br><br>
<label><b>SecretKeyId:</b></label><br><%=stsCredentials.getSecretAccessKey()%><br><br>
<label><b>SessionToken:</b></label><br><%=stsCredentials.getSessionToken()%>
</body>
</html>