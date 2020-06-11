# aws-mfa-login-helper

It generates a separate MFA profile under your AWS credential file with session token, helpful in a AWS MFA API access scenario, without putting a OTP token everytime during login.

Supports Google Authenticator, you will need to get the secret from AWS console.

Usage example:
```
aws-mfa-login-helper my_aws_profile_name ap-southeast-1 GOOGLEAUTHENTICATORSECRETKEY default
aws-mfa-login-helper my_aws_profile_name ap-southeast-1 GOOGLEAUTHENTICATORSECRETKEY /home/user/custom/location/credentials
```

A new profile with name appended "_mfa" will be generated under your AWS credential file.

```
[my_aws_profile_name]
aws_access_key_id     = masked
aws_secret_access_key = masked
region                = ap-southeast-1

[my_aws_profile_name_mfa]
aws_access_key_id     = masked
aws_secret_access_key = masked
aws_session_token     = masked
region                = ap-southeast-1
```

## License

MIT.
