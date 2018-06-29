<%@ page language="java" contentType="text/html; charset=UTF-8"
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
<form action="process.jsp">  
<label>Onelogin Username or Email</label><input type="text" name="onelogin_username_or_email" /><br/>  
<label>Onelogin Password</label><input type="password" name="onelogin_password"> <br/>  
<label>Onelogin App ID</label><input type="text" name="app_id"> <br/>  
<label>Onelogin Domain</label><input type="text" name="onelogin_domain"/><br/>
<input type="submit" value="Submit"/>  
</form>
</body>
</html>
