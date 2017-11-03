onelogin-aws-assume-role
========================

Assume an AWS Role and get temporary credentials using Onelogin.

Users will be able to choose from among multiple AWS roles in multiple AWS accounts when they sign in using OneLogin in order to assume an AWS Role and obtain temporary AWS acccess credentials.

This is really useful for customers that run complex environments with multiple AWS accounts, roles and many different people that need periodic access as it saves manually generating and managing AWS credentials.

This repository contains 2 examples of how to get the temporary AWS acccess credentials:
- onelogin-aws-assume-role-cli. Command Line Interface version.
- onelogin-aws-assume-role-jsp. An example web (JSP) version.

Most people want the CLI tool so check that you have the prequisites in place and get started.

## AWS and OneLogin prerequisites

The "[Configuring SAML for Amazon Web Services (AWS) with Multiple Accounts and Roles](https://support.onelogin.com/hc/en-us/articles/212802926-Configuring-SAML-for-Amazon-Web-Services-AWS-with-Multiple-Accounts-and-Roles)" guide explains how to:
 - Add the AWS Multi Account app to OneLogin
 - Configure OneLogin as an Identity Provider for each AWS account
 - Add or update AWS Roles to use OneLogin as the SAML provider
 - Add external roles to give OneLogin access to your AWS accounts
 - Complete your AWS Multi Account configuration in OneLogin

## Quick Start using precompiled binary
There is a precompiled [onelogin-aws-cli.jar](https://github.com/onelogin/onelogin-aws-cli-assume-role/blob/master/onelogin-aws-assume-role-cli/dist/onelogin-aws-cli.jar) file in the `onelogin-aws-assume-role-cli/dist` folder that you can download and start using this tool immediately.

Use the tool to generate AWS credentials and output them to the terminal.

```sh
> java -jar onelogin-aws-cli.jar
```

Or alternately save them to your AWS credentials file to enable faster access from any terminal.

```sh
> java -jar onelogin-aws-cli.jar --profile profilename
```

The credentials only last for 1 hour so you can also make it regenerate and update the credentials file by using the `--loop` option.

For [a more detail set of instructions](https://developers.onelogin.com/api-docs/1/samples/aws-cli) see the help guide.

## Installation

If you want to include the code in another project, extend it or just build your own binary you can find the source in these locations.

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
  * onelogin.sdk.region  Indicates where the region is hosted. Possible values: 'us' or 'eu'.

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

You can see detailed info about how to play with the onelogin-aws-cli.jar precompiled version at [OneLogin Developer site](https://developers.onelogin.com/api-docs/1/samples/aws-cli).

You can re-generate the jar by executing at the onelogin-aws-assume-role-cli folder the command:
```
mvn package
```

You can extend CLI functionality by using arguments. There are 4:

* loop Number of iterations (default value: 1)
* time Sleep time between iterations, in minutes (default value: 45) [Must be between 15 and 60]
* profile Save Temporal AWS credentials using that profile name (If not used, data is prompted instead saved in file)
* file Set a custom path to save the AWS credentials. (if not used, the default path is used)

### JSP

If you want to deploy the web example, at the Package Explorer, select the onelogin-aws-assume-role-jsp, 2nd bottom of the mouse and Run As > Run Server
Select a [Tomcat Server](http://crunchify.com/step-by-step-guide-to-setup-and-install-apache-tomcat-server-in-eclipse-development-environment-ide/) in order to deploy the server.
