onelogin-aws-assume-role
========================

Assume an AWS Role and cache credentials using Onelogin.

Users will be able to choose from among multiple AWS roles in multiple AWS accounts when they sign in using OneLogin in order to assume an AWS Role and get AWS temporal credentials.

This repository contains:
- onelogin-aws-assume-role-cli. Command Line Interface version.
- onelogin-aws-assume-role-jsp. A JSP (web) version.


AWS and Onelogin pre-requisites
-------------------------------

The "[Configuring SAML for Amazon Web Services (AWS) with Multiple Accounts and Roles](https://support.onelogin.com/hc/en-us/articles/212802926-Configuring-SAML-for-Amazon-Web-Services-AWS-with-Multiple-Accounts-and-Roles)" guide explains how to:
 - Add the AWS Multi Account app to OneLogin
 - Configure OneLogin as an Identity Provider for each AWS account
 - Add or update AWS Roles to use OneLogin as the SAML provider
 - Add external roles to give OneLogin access to your AWS accounts
 - Complete your AWS Multi Account configuration in OneLogin

## Installation
### Hosting
The project is hosted at github. You can download it from:
* Lastest release: https://github.com/onelogin/onelogin-aws-cli-assume-role/releases/latest
* Master repo: https://github.com/onelogin/onelogin-aws-cli-assume-role/tree/master

### Dependencies

* [com.amazonaws:aws-java-sdk](https://github.com/aws/aws-sdk-java)
* [com.onelogin:onelogin-java-sdk](https://github.com/onelogin/onelogin-java-sdk)
* [com.onelogin:java-saml-core](https://github.com/onelogin/java-saml)
* javax.servlet:servlet-api Required by the Web project

## Working with the github repository code and Eclipse.

### Get the code.
The code is hosted at github. You can download it from:
* Lastest release: https://github.com/onelogin/onelogin-aws-cli-assume-role/releases/latest
* Master repo: https://github.com/onelogin/onelogin-aws-cli-assume-role/tree/master

### Adding onelogin-aws-assume-role-cli or onelogin-aws-assume-role-jsp as a project
1. Open Eclipse and set a workspace
2. File > Import > Maven : Existing Maven Projects > Select the path where the repository was downloaded, resolve the Workspace project folder and select the pom.xml

### Deploy the onelogin-aws-assume-role-jsp

At the Package Explorer, select the onelogin-aws-assume-role-jsp, 2nd bottom of the mouse and Run As > Run Server
Select a [Tomcat Server](http://crunchify.com/step-by-step-guide-to-setup-and-install-apache-tomcat-server-in-eclipse-development-environment-ide/) in order to deploy the server.

## Getting started

### Settings

Both projects uses a settings file, where [OneLogin SDK properties](https://github.com/onelogin/onelogin-java-sdk#settings) are placed, that can be found at *src/resources* folder:

* *onelogin.sdk.properties* used onelogin-java-sdk. That file contains 3 settings parameters:
  * onelogin.sdk.client_id  Onelogin OAuth2 client ID
  * onelogin.sdk.client_secret  Onelogin OAuth2 client secret
  * onelogin.sdk.instance  Indicates where the instance is hosted. Possible values: 'us' or 'eu'.

### How it works

#### Step 1. Provide Onelogin data.

- Provide Onelogin's username/mail and password to authenticate the user
- Provide the Onelogin's App ID to identify the AWS app
- Provide the domain of your Onelogin's instance.

With that data, a SAMLResponse is retrieved. And possible AWS Role are retrieved.

#### Step 2. Select AWS Role to be assumed.

- Provide the desired AWS Role to be assumed.
- Provide the AWS Region instance (required in order to execute the AWS API call).

#### Step 3. AWS Credentials retrieved.

A temporal AWS AccessKey and secretKey are retrieved in addition to a sessionToken.
Those data can be used to generate an AWS BasicSessionCredentials to be used in any AWS API java sdk:

```
BasicSessionCredentials temporaryCredentials = new BasicSessionCredentials(
    assumeRoleWithSAMLResult.getCredentials().getAccessKeyId(),
    assumeRoleWithSAMLResult.getCredentials().getSecretAccessKey(),
    assumeRoleWithSAMLResult.getCredentials().getSessionToken()
);

AmazonS3Client s3 = new AmazonS3Client(temporaryCredentials); 
```

## Use the JAR file.

The onelogin-aws-assume-role-cli provides 2 jars:
* onelogin-aws-assume-role-cli.jar
* onelogin-aws-assume-role-cli-jar-with-dependencies.jar

You can get them executing
```
mvn package
```

You can execute each jar with:
```
java -jar onelogin-aws-assume-role-cli-jar-with-dependencies.jar
```

The jar uses OneLogin SDK so a [onelogin.sdk.properties](https://github.com/onelogin/onelogin-aws-cli-assume-role/blob/master/onelogin-aws-assume-role-cli/src/main/resources/onelogin.sdk.properties) file need to be provided on the same folder than the jar.