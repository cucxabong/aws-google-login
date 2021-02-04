What's this
===============
This command-line tool allows you to acquire AWS temporary (STS) credentials using Google Apps as a federated (Single Sign-On, or SSO) provider. This project was inspired from [aws-google-auth](https://github.com/cevoaustralia/aws-google-auth)
 and the help of [playwright-go](https://github.com/mxschmitt/playwright-go) for the interactive Graphic User Interface (GUI)

Features
===============
- Interactive Authentication
- Multi-Factor Authentication (Hardware & Software)
- Caching SAML assertion document
- Environment variable supported
- Captcha input supported

Usage
=====
```bash
aws-google-login --help
NAME:
   aws-google-login - Acquire temporary AWS credentials via Google SSO (SAML v2)

USAGE:
   aws-google-login [global options] command [command options] [arguments...]

COMMANDS:
   help, h  Shows a list of commands or help for one command

GLOBAL OPTIONS:
   --list-roles, -l            Listing AWS Role(s) were associated with (authenticated) user (default: false)
   --duration value, -d value  Session Duration which is used to assume to a role (default: 3600)
   --sp-id value, -s value     Google SSO SP identifier [$GOOGLE_SP_ID]
   --idp-id value, -i value    Google SP identifier [$GOOGLE_IDP_ID]
   --role-arn value, -r value  AWS Role Arn for assuming to
   --saml-file value           Path to file contains SAML Assertion (default: "~/.aws_google_login_cache.txt")
   --no-cache                  Force to re-authenticate (default: false)
   --get-saml-assertion        Getting SAML assertion XML (default: false)
   --export                    Print export line for working with aws cli (default: false)
   --help, -h                  show help (default: false)
```
