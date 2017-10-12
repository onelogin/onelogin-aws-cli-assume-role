onelogin-aws-assume-role
========================

Assume an AWS Role and get temporary credentials using Onelogin.

Users will be able to choose from among multiple AWS roles in multiple AWS accounts when they sign in using OneLogin in order to assume an AWS Role and obtain temporary AWS acccess credentials.

This is really useful for customers that run complex environments with multiple AWS accounts, roles and many different people that need periodic access as it saves manually generating and managing AWS credentials.

This repository contains:
- onelogin-aws-assume-role-cli. Command Line Interface version.
- onelogin-aws-assume-role-jsp. An example web (JSP) version.

If you want to get up and running quickly then we recommend using a precompiled distribution [onelogin-aws-cli.jar](https://github.com/onelogin/onelogin-aws-cli-assume-role/blob/master/onelogin-aws-assume-role-cli/dist/onelogin-aws-cli.jar) inside the `dist` folder. Follow [those instructions](https://developers.onelogin.com/api-docs/1/samples/aws-cli).

You can re-generate the jar by executing at the onelogin-aws-assume-role-cli folder the command:
```
mvn package
```

## AWS and OneLogin pre-requisites

The "[Configuring SAML for Amazon Web Services (AWS) with Multiple Accounts and Roles](https://support.onelogin.com/hc/en-us/articles/212802926-Configuring-SAML-for-Amazon-Web-Services-AWS-with-Multiple-Accounts-and-Roles)" guide explains how to:
 - Add the AWS Multi Account app to OneLogin
 - Configure OneLogin as an Identity Provider for each AWS account
 - Add or update AWS Roles to use OneLogin as the SAML provider
 - Add external roles to give OneLogin access to your AWS accounts
 - Complete your AWS Multi Account configuration in OneLogin

## Installation
### Hosting

#### Github

The project is hosted at github. You can download it from:
* Lastest release: https://github.com/onelogin/onelogin-aws-cli-assume-role/releases/latest
* Master repo: https://github.com/onelogin/onelogin-aws-cli-assume-role/tree/master

#### Maven

The toolkit is hosted at [Sonatype OSSRH (OSS Repository Hosting)](http://central.sonatype.org/pages/ossrh-guide.html) that is synced to the Central Repository.

Install it as a maven dependecy:

aws-cli
```
  <dependency>
      <groupId>com.onelogin</groupId>
      <artifactId>onelogin-aws-assume-role-cli</artifactId>
      <version>1.0.0</version>
  </dependency>
```

aws-jsp
```
  <dependency>
      <groupId>com.onelogin</groupId>
      <artifactId>onelogin-aws-assume-role-jsp</artifactId>
      <version>1.0.0</version>
  </dependency>
```

### Dependencies

It works with Java7 and Java8.

* [com.amazonaws:aws-java-sdk](https://github.com/aws/aws-sdk-java)
* [com.onelogin:onelogin-java-sdk](https://github.com/onelogin/onelogin-java-sdk)
* [com.onelogin:java-saml-core](https://github.com/onelogin/java-saml)
* javax.servlet:servlet-api Required by the example Web project

## Getting started

### Settings

Both projects uses a settings file, where [OneLogin SDK properties](https://github.com/onelogin/onelogin-java-sdk#settings) are placed, that can be found at *src/resources* folder:

* *onelogin.sdk.properties* used by onelogin-java-sdk. That file contains 3 settings parameters:
  * onelogin.sdk.client_id  Onelogin OAuth2 client ID
  * onelogin.sdk.client_secret  Onelogin OAuth2 client secret
  * onelogin.sdk.instance  Indicates where the instance is hosted. Possible values: 'us' or 'eu'.

### How the process works

#### Step 1. Provide OneLogin data.

- Provide OneLogin's username/mail and password to authenticate the user
- Provide the OneLogin's App ID to identify the AWS app
- Provide the domain of your OneLogin's instance.

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

## Usage

## Working with the github repository code and Eclipse.

Adding onelogin-aws-assume-role-cli or onelogin-aws-assume-role-jsp as a project
1. Open Eclipse and set a workspace
2. File > Import > Maven : Existing Maven Projects > Select the path where the repository was downloaded, resolve the Workspace project folder and select the pom.xml

### CLI

In order to execute the cli code, at the Package Explorer, select the onelogin-aws-assume-role-cli, 2nd bottom of the mouse and Run As > Java application and select the OneloginAWSCLI.

### JSP 

If you want to deploy the web example, at the Package Explorer, select the onelogin-aws-assume-role-jsp, 2nd bottom of the mouse and Run As > Run Server
Select a [Tomcat Server](http://crunchify.com/step-by-step-guide-to-setup-and-install-apache-tomcat-server-in-eclipse-development-environment-ide/) in order to deploy the server.