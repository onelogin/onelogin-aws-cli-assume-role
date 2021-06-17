import argparse
import configparser
import os
import time
from typing import Dict, Any, List, Tuple

import boto3
import botocore.config
from onelogin.saml2.response import OneLogin_Saml2_Response
from onelogin.api.client import OneLoginClient


def check_device_exists(devices: List, device_id: int) -> bool:
    return any([device.id == device_id for device in devices])


def get_choice(prompt: str, options: List) -> int:
    print("Options:")
    for idx, opt in enumerate(options):
        print(f"{idx} | {opt}")
    return get_selection(prompt, len(options))


def get_selection(prompt: str, size: int, start: int = 0) -> int:
    selection = start - 1
    end = start + size - 1
    while selection < start or selection > end:
        selection = int(input(f"{prompt} [{start}-{end}]"))
    return selection


def split_role_string(role_data: str) -> Tuple[str, str]:
    role_info = role_data.split(':')
    account_id = role_info[4]
    role_name = role_info[5].replace('role/', '')

    return account_id, role_name


class OneLoginConnection(object):
    def __init__(self):
        self.__time: int = 45
        self.__loop: int = 1
        self.__profile: str = None
        self.__file = None
        self.__username: str = None
        self.__password: str = None
        self.__subdomain: str = None
        self.__onelogin_client_id: str = None
        self.__onelogin_client_secret: str = None
        self.__onelogin_region: str = "us"
        self.__appid: str = None
        self.__region: str = None
        self.__aws_account_id: str = None
        self.__aws_role_name: str = None
        self.__duration: int = 900

        self.__ol_client: OneLoginClient = None

    def parse_command_line(self) -> None:
        parser = argparse.ArgumentParser()
        parser.add_argument("-t", "--time", required=False, help="Sleep time between iterations, in minutes",
                            type=int, metavar='[15-60]', default=45)  # TODO - Range limit action?
        parser.add_argument("-l", "--loop", required=False, help="Number of iterations", type=int, default=1)
        parser.add_argument("-p", "--profile", required=False,
                            help="Save temporary AWS credentials using that profile name", default="default")
        parser.add_argument("-f", "--file", required=False,
                            help="Set a custom path to save the AWS credentials. (if not "
                                 "used, default AWS path is used)", default=None)
        parser.add_argument("-r", "--region", required=True, help="Set the AWS region.")
        parser.add_argument("-a", "--appid", required=True, help="Set AWS App ID.")
        parser.add_argument("-d", "--subdomain", required=True, help="OneLogin Instance Sub Domain.")
        parser.add_argument("-u", "--username", required=True, help="OneLogin username.")
        parser.add_argument("--password", required=True, help="OneLogin password.")
        parser.add_argument("--aws-account-id", required=False, help="AWS Account ID.")
        parser.add_argument("--aws-role-name", required=False, help="AWS Role Name.")
        parser.add_argument("-z", "--duration", required=False, help="Desired AWS Credential Duration",
                            metavar='[900, 43200]', type=int, default=900)  # TODO - Range limit?
        parser.add_argument("--onelogin-client-id", required=False, help="A valid OneLogin API client_id")
        parser.add_argument("--onelogin-client-secret", required=False, help="A valid OneLogin API client_secret")
        parser.add_argument("--onelogin-region", required=False, help="OneLogin region. us or eu",
                            choices=["us", "eu"], default="us")

        args = parser.parse_args()
        args.time = max(min(args.time, 60), 15)
        args.duration = max(min(args.duration, 43200), 900)
        # TODO - action groups?
        if bool(args.aws_account_id) != bool(args.aws_role_name):
            raise Exception("--aws-account-id and --aws-role-name need to be set together")
        if bool(args.onelogin_client_id) != bool(args.onelogin_client_secret):
            raise Exception("--onelogin-client-id and --onelogin-client-secret need to be set together")

        # Assign the values
        class_name = str(type(self))
        class_name = class_name[class_name.find('.') + 1:class_name.rfind('\\') - 1]
        for key, value in vars(args).items():
            self.__setattr__(f'_{class_name}__{key}', value)

    def verify_token(self, device_id_str, state_token: str, otp_token: str,
                     mfa_verify_info: Dict[str, str]) -> Dict[str, Any]:
        result = dict()
        try:
            saml_endpoint_response_after_verify = self.__ol_client.get_saml_assertion_verifying(self.__appid,
                                                                                                device_id_str,
                                                                                                state_token, otp_token,
                                                                                                None)
            mfa_verify_info["otp_token"] = otp_token
            saml_response = saml_endpoint_response_after_verify.saml_response
            result["saml_response"] = saml_response
            result["mfa_verify_info"] = mfa_verify_info
        except:
            otp_token = input("The OTP token was invalid, please introduce a new one: ")
            result = self.verify_token(device_id_str, state_token, otp_token, mfa_verify_info)

        return result

    def get_saml_response(self, mfa_verify_info: Dict[str, str], ip: str = None) -> Dict[str, str]:
        device_id_str = None
        result = dict()
        saml_endpoint_response = None
        status = "pending"
        while status == "pending":
            # Sleep for 30 seconds
            if saml_endpoint_response:
                time.sleep(30)

            saml_endpoint_response = self.__ol_client.get_saml_assertion(self.__username,
                                                                         self.__password, self.__appid,
                                                                         self.__subdomain, ip)
            status = saml_endpoint_response.type

        if status == "success":
            if saml_endpoint_response.mfa:
                mfa = saml_endpoint_response.mfa
                devices = mfa.devices
                if not mfa_verify_info:
                    print("MFA Required")
                else:
                    device_id_str = mfa_verify_info.get("deviceId")  # TODO - snake case?
                    if not check_device_exists(devices, int(device_id_str)):
                        print(f"The device selected with ID {device_id_str} is not available anymore")
                        print(f"These are the devices available now:")
                        mfa_verify_info = None

                if not mfa_verify_info:
                    if len(devices) == 1:
                        device_selection = devices[0]
                    else:
                        device_selection = devices[get_choice("Select the desired MFA Device",
                                                              [f" {idx} | {device.type}" for idx, device in
                                                               enumerate(devices)])]

                    device_id_str = str(device_selection.id)

                    otp_token = input(f"Enter the OTP Token for {device_selection.type}: ")
                    state_token = mfa.state_token
                    mfa_verify_info = dict()
                    mfa_verify_info["otp_token"] = otp_token
                    mfa_verify_info["state_token"] = state_token
                else:
                    otp_token = mfa_verify_info["otp_token"]
                    state_token = mfa_verify_info["state_token"]

                result = self.verify_token(device_id_str, state_token, otp_token, mfa_verify_info)

            else:
                saml_response = saml_endpoint_response.saml_response
                result["saml_response"] = saml_response
                result["mfa_verify_info"] = mfa_verify_info

        return result

    def connect(self):
        self.__ol_client = OneLoginClient(self.__onelogin_client_id, self.__onelogin_client_secret,
                                          self.__onelogin_region)
        self.__ol_client.get_access_token()
        try:
            mfa_verify_info = dict()

            role_arn = ''
            principal_arn = ''
            default_aws_region = ''  # TODO - get default region

            for ij in range(self.__loop):
                if ij == 0:
                    print(f"One Login Username: {self.__username}")
                    print(f"One Login Password: {'****'}")
                    print(f"AWS App ID: {self.__appid}")
                    print(f"One Login Instance Sub Domain: {self.__subdomain}")
                else:
                    # Sleep for a specified number of minutes
                    time.sleep(self.__time)
                    pass

                result = self.get_saml_response(mfa_verify_info, None)
                mfa_verify_info = result.get("mfa_verify_info")
                saml_response = result.get("saml_response")

                if ij == 0:
                    response = OneLogin_Saml2_Response(None, saml_response)
                    if "https://aws.amazon.com/SAML/Attributes/Role" not in response.get_attributes().keys():
                        raise Exception("SAMLResponse from Identity Provider does not contain AWS Role info")

                    role_data_list = response.get_attributes().get('https://aws.amazon.com/SAML/Attributes/Role')
                    role_data = list(role_data_list)
                    if self.__aws_account_id:
                        role_data = [role for role in role_data_list if role.split(":")[4] == self.__aws_account_id]

                    selected_role = ''

                    if len(role_data) == 1 and role_data[0]:
                        account_id, role_name = split_role_string(role_data[0])
                        selected_role = role_data[0]
                    elif len(role_data) > 1:
                        print('Available AWS Roles')
                        roles_by_app = dict()
                        for idx, role in enumerate(role_data):
                            account_id, role_name = split_role_string(role.split(',')[0])
                            if account_id not in roles_by_app.keys():
                                roles_by_app[account_id] = dict()
                            roles_by_app[account_id][role_name] = idx

                        role_selection = roles_by_app.get(self.__aws_account_id, dict()).get(self.__aws_role_name, None)
                        if role_selection is None:
                            if self.__aws_account_id and self.__aws_role_name:
                                print(
                                    f"SAMLResponse from Identity Provider does not contain available AWS Role: {self.__aws_role_name} for AWS Account: {self.__aws_account_id}")
                            role_selection = get_choice("Select the desired role",
                                                        [f'{role} (Account {account})' for account in
                                                         roles_by_app.keys()
                                                         for role in roles_by_app[account].keys()])
                        selected_role = role_data[role_selection]
                    else:
                        raise Exception(
                            "SAMLResponse from Identity Provider does not contain available AWS Role for this user")

                    print(f"Role selected: {role_name} (Account {account_id})")

                    if selected_role:
                        selected_role_data = selected_role.split(',')
                        role_arn = selected_role_data[0]
                        principal_arn = selected_role_data[1]

                if ij == 0:
                    if not self.__region:
                        self.__region = input(f"AWS Region ({default_aws_region}):")
                        if not self.__region or self.__region == "-":
                            self.__region = default_aws_region
                    else:
                        print(f"AWS Region: {self.__region}")

                my_config = botocore.config.Config(region_name=self.__region)
                sts_client = boto3.client("sts", config=my_config)
                assume_role_with_saml_result = sts_client.assume_role_with_saml(RoleArn=role_arn,
                                                                                PrincipalArn=principal_arn,
                                                                                SAMLAssertion=saml_response,
                                                                                DurationSeconds=self.__duration)
                sts_credentials = assume_role_with_saml_result['Credentials']
                assumed_role_user = assume_role_with_saml_result['AssumedRoleUser']

                if not self.__profile and not self.__file:
                    action = "set" if os.name == "win" else "export"
                    print("-----------------------------------------------------------------------")
                    print("Success!")
                    print(f"Assumed Role User: {assumed_role_user.arn}")
                    print("Temporary AWS Credentials Granted via OneLogin ")
                    print(f"It will expire at {sts_credentials['Expiration']}")
                    print("Copy/Paste to set these as environment variables")
                    print("-----------------------------------------------------------------------")
                    print(f"{action} AWS_SESSION_TOKEN={sts_credentials['SessionToken']}")
                    print(f"{action} AWS_ACCESS_KEY_ID={sts_credentials['AccessKeyId']}")
                    print(f"{action} AWS_SECRET_ACCESS_KEY={sts_credentials['SecretAccessKey']}")
                else:
                    if not self.__file:
                        self.__file = os.path.join(os.path.expanduser('~'), '.aws/credentials')
                    if not self.__profile:
                        self.__profile = "default"

                    # Update profile
                    parser = configparser.ConfigParser()
                    parser.read(self.__file)
                    if self.__profile not in parser.sections():
                        parser.add_section(self.__profile)
                    parser.set(self.__profile, 'aws_access_key_id', sts_credentials['AccessKeyId'])
                    parser.set(self.__profile, 'aws_secret_access_key', sts_credentials['SecretAccessKey'])
                    parser.set(self.__profile, 'aws_session_token', sts_credentials['SessionToken'])
                    parser.set(self.__profile, 'expiration', str(sts_credentials['Expiration']))
                    parser.set(self.__profile, 'region', self.__region)

                    with open(self.__file, 'w') as credentials_file:
                        parser.write(credentials_file)
        except:
            raise


def main() -> None:
    onelogin_client = OneLoginConnection()
    onelogin_client.parse_command_line()
    onelogin_client.connect()


if __name__ == "__main__":
    main()
