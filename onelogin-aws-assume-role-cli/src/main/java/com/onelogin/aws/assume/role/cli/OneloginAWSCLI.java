package com.onelogin.aws.assume.role.cli;
import java.util.concurrent.TimeUnit;
import java.util.HashMap;
import java.util.List;
import java.util.Scanner;
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
public class OneloginAWSCLI {
    public static void main(String[] args) throws Exception {
        // OneLogin Java SDK Client
        Client olClient = new Client();
        olClient.getAccessToken();
        Scanner scanner = new Scanner(System.in);
        try {
            // Capture OneLogin Account Details
            System.out.print("OneLogin Username: ");
            String oneloginUsernameOrEmail = scanner.next();
            System.out.print("OneLogin Password: ");
            String oneloginPassword = scanner.next();
            System.out.print("AWS App ID: ");
            String appId = scanner.next();
            System.out.print("Onelogin Instance Sub Domain: ");
            String oneloginDomain = scanner.next();
            SAMLEndpointResponse samlEndpointResponse = olClient.getSAMLAssertion(oneloginUsernameOrEmail, oneloginPassword,
                    appId, oneloginDomain);
            String status = samlEndpointResponse.getType();
            while (status.equals("pending")) {
                TimeUnit.SECONDS.sleep(30);
                samlEndpointResponse = olClient.getSAMLAssertion(oneloginUsernameOrEmail, oneloginPassword, appId,
                        oneloginDomain);
                status = samlEndpointResponse.getType();
            }
            String samlResponse = null;
            if (status.equals("success")) {
                if (samlEndpointResponse.getMFA() != null) {
                    MFA mfa = samlEndpointResponse.getMFA();
                    List<Device> devices = mfa.getDevices();
                    System.out.print("MFA required");
                    Device device;
                    for (int i = 0; i < devices.size(); i++) {
                        device = devices.get(i);
                        System.out.print(" - " + device.getType() + "ID: " + device.getID());
                    }
                    System.out.print("\nSelect the desired Device ID: ");
                    String deviceId = scanner.next();
                    System.out.print("OTP Token: ");
                    String otpToken = scanner.next();
                    SAMLEndpointResponse samlEndpointResponseAfterVerify = olClient.getSAMLAssertionVerifying(appId, deviceId,
                            mfa.getStateToken(), otpToken, null);
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
                    Integer roleSelection = Integer.valueOf(scanner.next());
                    selectedRole = roleData.get(roleSelection);
                } else {
                    selectedRole = roleData.get(0);
                }
                String[] selectedRoleData = selectedRole.split(",");
                String roleArn = selectedRoleData[0];
                String principalArn = selectedRoleData[1];
                AssumeRoleWithSAMLRequest assumeRoleWithSAMLRequest = new AssumeRoleWithSAMLRequest()
                        .withPrincipalArn(principalArn).withRoleArn(roleArn).withSAMLAssertion(samlResponse);
                System.out.print("AWS Region (Ex: eu-west-1): ");
                String awsRegion = scanner.next();
                AWSSecurityTokenServiceClientBuilder stsBuilder = AWSSecurityTokenServiceClientBuilder.standard();
                AWSSecurityTokenService stsClient = stsBuilder.withRegion(awsRegion).build();
                AssumeRoleWithSAMLResult assumeRoleWithSAMLResult = stsClient.assumeRoleWithSAML(assumeRoleWithSAMLRequest);
                Credentials stsCredentials = assumeRoleWithSAMLResult.getCredentials();
                AssumedRoleUser assumedRoleUser = assumeRoleWithSAMLResult.getAssumedRoleUser();
                System.out.println("AssumedRoleUser: " + assumedRoleUser.getArn());
                System.out.println("AccessKeyId: " + stsCredentials.getAccessKeyId());
                System.out.println("SecretKeyId: " + stsCredentials.getSecretAccessKey());
                System.out.println("SessionToken: " + stsCredentials.getSessionToken());
            }
        }
        finally {
            scanner.close();
        }
    }
}