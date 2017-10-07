package com.onelogin.aws.assume.role.cli;


import java.io.InputStream;
import java.util.concurrent.TimeUnit;
import java.util.HashMap;
import java.util.List;
import java.util.Scanner;

import com.amazonaws.auth.AWSCredentials;
import com.amazonaws.auth.AWSStaticCredentialsProvider;
import com.amazonaws.auth.PropertiesCredentials;
//import com.amazonaws.auth.BasicSessionCredentials;
//import com.amazonaws.services.s3.AmazonS3Client;
//import com.amazonaws.services.securitytoken.model.AssumeRoleRequest;
//import com.amazonaws.services.securitytoken.model.AssumeRoleResult;
import com.amazonaws.services.securitytoken.AWSSecurityTokenService;
import com.amazonaws.services.securitytoken.AWSSecurityTokenServiceClientBuilder;
import com.amazonaws.services.securitytoken.model.AssumeRoleWithSAMLRequest;
import com.amazonaws.services.securitytoken.model.AssumeRoleWithSAMLResult;
import com.amazonaws.services.securitytoken.model.AssumedRoleUser;
import com.amazonaws.services.securitytoken.model.Credentials;

import com.onelogin.saml2.authn.SamlResponse;
import com.onelogin.saml2.http.HttpRequest;

import com.onelogin.sdk.conn.Client;
import com.onelogin.sdk.model.Device;
import com.onelogin.sdk.model.MFA;
import com.onelogin.sdk.model.SAMLEndpointResponse;

public class OneloginAWSCLI 
{
    public static void main( String[] args ) throws Exception
    {
    	Client olClient = new Client();
        olClient.getAccessToken();

        // User Input data 
        System.out.print("Username: ");
        Scanner scanner = new Scanner(System.in);
        String oneloginUsernameOrEmail = scanner.next();

        System.out.print("Password: ");
        scanner = new Scanner(System.in);
        String oneloginPassword = scanner.next();

        System.out.print("AWS App ID: ");
        scanner = new Scanner(System.in);
        String appId = scanner.next();

        System.out.print("Onelogin Instance Domain: ");
        scanner = new Scanner(System.in);
        String oneloginDomain = scanner.next();

        SAMLEndpointResponse samlEndpointResponse = olClient.getSAMLAssertion(oneloginUsernameOrEmail, oneloginPassword, appId, oneloginDomain);

        String status = samlEndpointResponse.getType();
        while(status.equals("pending")) {
        	TimeUnit.SECONDS.sleep(30);
                samlEndpointResponse = olClient.getSAMLAssertion(oneloginUsernameOrEmail, oneloginPassword, appId, oneloginDomain);
        	status = samlEndpointResponse.getType();
        }

        String samlResponse = null;
        if (status.equals("success")) {
        	if (samlEndpointResponse.getMFA() != null) {
        		MFA mfa = samlEndpointResponse.getMFA();
        		List<Device> devices = mfa.getDevices();
        		System.out.print("MFA required");
        		Device device;
        		for (int i=0; i < devices.size(); i++) {
        			device = devices.get(i);
        			System.out.print(" - " + device.getType() + "ID: "+ device.getID());
        		}
        		System.out.print("\nSelect the desired Device ID: ");
                scanner = new Scanner(System.in);
                String deviceId = scanner.next();

        		System.out.print("OTP Token: ");
                scanner = new Scanner(System.in);
                String otpToken = scanner.next();

                SAMLEndpointResponse samlEndpointResponseAfterVerify = olClient.getSAMLAssertionVerifying(appId, deviceId, mfa.getStateToken(), otpToken, null);
                samlResponse = samlEndpointResponseAfterVerify.getSAMLResponse();

        	} else {
        		samlResponse = samlEndpointResponse.getSAMLResponse();
        	}
        }
        HttpRequest simulatedRequest = new HttpRequest("http://example.com");
        simulatedRequest = simulatedRequest.addParameter("SAMLResponse", samlResponse);

        SamlResponse samlResponseObj = new SamlResponse(null, simulatedRequest);
        HashMap<String, List<String>> attributes = samlResponseObj.getAttributes();
		if (!attributes.containsKey("https://aws.amazon.com/SAML/Attributes/Role")) {
			System.out.print("SAMLResponse from Identity Provider does not contain AWS Role info");
		} else {
			String selectedRole;
			List<String> roleData = attributes.get("https://aws.amazon.com/SAML/Attributes/Role");
			if (roleData.size() > 1) {
				System.out.println("Available Roles...");
				for (int i = 0; i < roleData.size(); i++) {
					String[] roleInfo = roleData.get(i).split(":");
					String accountId = roleInfo[4];
					String roleName = roleInfo[5].replace("role/", "");
					System.out.println(" " + i + ". " + roleName + "(Account " + accountId + ")");
				}
				System.out.print("Select the desired Role [0-" + (roleData.size() - 1) + "]:");
				scanner = new Scanner(System.in);
                Integer roleSelection = Integer.valueOf(scanner.next());
                selectedRole = roleData.get(roleSelection);
			} else {
				selectedRole = roleData.get(0);
			}

			String[] selectedRoleData = selectedRole.split(","); 
			String roleArn = selectedRoleData[0];
			String principalArn = selectedRoleData[1];
			AssumeRoleWithSAMLRequest assumeRoleWithSAMLRequest = new AssumeRoleWithSAMLRequest()
					.withPrincipalArn(principalArn)
					.withRoleArn(roleArn)
					.withSAMLAssertion(samlResponse);

	    	OneloginAWSCLI awscli = new OneloginAWSCLI();    	
			InputStream credentialStream = awscli.getFileInputStream("onelogin.aws.properties"); 
			AWSCredentials awsCredentials = new PropertiesCredentials(credentialStream);

    		System.out.print("AWS Region (Ex: eu-west-1): ");
            scanner = new Scanner(System.in);
            String awsRegion = scanner.next();

			AWSSecurityTokenServiceClientBuilder stsBuilder = AWSSecurityTokenServiceClientBuilder.standard().withCredentials(new AWSStaticCredentialsProvider(awsCredentials));
			AWSSecurityTokenService stsClient = stsBuilder.withRegion(awsRegion).build();

			AssumeRoleWithSAMLResult assumeRoleWithSAMLResult = stsClient.assumeRoleWithSAML(assumeRoleWithSAMLRequest);

			Credentials stsCredentials = assumeRoleWithSAMLResult.getCredentials();
			AssumedRoleUser assumedRoleUser = assumeRoleWithSAMLResult.getAssumedRoleUser();
			System.out.println("AssumedRoleUser: " + assumedRoleUser.getArn());
			System.out.println("AccessKeyId: " + stsCredentials.getAccessKeyId());
			System.out.println("SecretKeyId: " + stsCredentials.getSecretAccessKey());
			System.out.println("SessionToken: " + stsCredentials.getSessionToken());

/*
 			BasicSessionCredentials temporaryCredentials = new BasicSessionCredentials(
                    assumeRoleWithSAMLResult.getCredentials().getAccessKeyId(),
                    assumeRoleWithSAMLResult.getCredentials().getSecretAccessKey(),
                    assumeRoleWithSAMLResult.getCredentials().getSessionToken());

             AmazonS3Client s3 = new AmazonS3Client(temporaryCredentials); 
*/

		}
    }

    private InputStream getFileInputStream(String propFileName) {
    	return getClass().getClassLoader().getResourceAsStream(propFileName);
    }
}
