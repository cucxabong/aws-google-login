package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"text/template"

	"encoding/json"

	awslogin "github.com/cucxabong/aws-google-login"

	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/urfave/cli/v2"
)

type Option struct {
	spID             string
	idpID            string
	Duration         int64
	ListRole         bool
	SamlFile         string
	NoCache          bool
	RoleArn          string
	GetSamlAssertion bool
	Export           bool
}

func parseOption(c *cli.Context) (*Option, error) {
	opt := &Option{}

	opt.spID = c.String("sp-id")
	opt.idpID = c.String("idp-id")
	opt.Duration = c.Int64("duration")
	opt.ListRole = c.Bool("list-roles")
	opt.SamlFile = c.String("saml-file")
	opt.NoCache = c.Bool("no-cache")
	opt.GetSamlAssertion = c.Bool("get-saml-assertion")
	opt.Export = c.Bool("export")
	if c.IsSet("role-arn") {
		opt.RoleArn = c.String("role-arn")
	}

	opt.SamlFile = awslogin.NormalizePath(opt.SamlFile)

	return opt, nil
}

func writeSamlAssertion(filename, assertion string) error {
	return ioutil.WriteFile(filename, []byte(assertion), 0600)
}

func handler(c *cli.Context) error {
	var assertion string
	var err error
	opt, err := parseOption(c)
	if err != nil {
		return err
	}

	if !opt.NoCache {
		if _, err := os.Stat(opt.SamlFile); err == nil {
			// Read assertion from file
			data, err := ioutil.ReadFile(opt.SamlFile)
			if err != nil {
				return err
			}
			if awslogin.IsValidSamlAssertion(string(data)) {
				assertion = string(data)
			}
		}
	}

	if assertion == "" {
		g := awslogin.NewGoogleConfig(opt.idpID, opt.spID)
		assertion, err = g.Login()
		if err != nil {
			return err
		}
		if opt.GetSamlAssertion {
			fmt.Println(assertion)
			return nil
		}
		writeSamlAssertion(opt.SamlFile, assertion)
	}

	amz := awslogin.NewAmazonConfig(assertion, opt.Duration)

	if opt.ListRole {
		return listRolesHandler(amz)
	}

	if opt.RoleArn != "" {
		return assumeSingleRoleHandler(amz, opt.RoleArn, opt.Export)
	}

	return interactiveAssumeRole(amz, opt.Export)
}

func printExportline(stsCred *sts.Credentials) error {
	t := template.Must(template.New("aws-export-line").Parse(AWS_CREDS_EXPORT_TEMPLATE))
	return t.Execute(os.Stdout, stsCred)
}

func assumeSingleRoleHandler(amz *awslogin.Amazon, roleArn string, export bool) error {
	var principalArn string
	roles, err := amz.ParseRoles()
	if err != nil {
		return err
	}

	for _, v := range roles {
		if roleArn == v.RoleArn {
			principalArn = v.PrincipalArn
			break
		}
	}

	// The role user specified not be configured for user account
	if principalArn == "" {
		return fmt.Errorf("role is not configured for your user")
	}

	stsCreds, err := amz.AssumeRole(roleArn, principalArn)
	if err != nil {
		return err
	}

	if export {
		err = printExportline(stsCreds)
		if err != nil {
			return fmt.Errorf("unable to render export line %v", err)
		}
		fmt.Printf("Credentials Expiration: %q\n", stsCreds.Expiration.String())
		return nil
	}

	// JSON output to stdout
	jsonData, err := json.Marshal(stsCreds)
	if err != nil {
		return err
	}

	fmt.Println(string(jsonData))

	return nil
}

func listRolesHandler(amz *awslogin.Amazon) error {
	roles, err := amz.ParseRoles()
	if err != nil {
		return err
	}

	jsonData, err := json.Marshal(roles)
	if err != nil {
		return err
	}

	fmt.Println(string(jsonData))

	return nil
}

func main() {
	app := &cli.App{
		Name:   "aws-google-login",
		Usage:  "Acquire temporary AWS credentials via Google SSO (SAML v2)",
		Action: handler,
	}
	app.Flags = []cli.Flag{
		&cli.BoolFlag{
			Name:    "list-roles",
			Aliases: []string{"l"},
			Usage:   "Listing AWS Role(s) were associated with (authenticated) user",
			Value:   false,
		},
		&cli.Int64Flag{
			Name:    "duration",
			Aliases: []string{"d"},
			Usage:   "Session Duration which is used to assume to a role",
			Value:   awslogin.DEFAULT_SESSION_DURATION,
		},
		&cli.StringFlag{
			Name:     "sp-id",
			Aliases:  []string{"s"},
			Usage:    "Google SSO SP identifier",
			Required: true,
			EnvVars:  []string{"GOOGLE_SP_ID"},
		},
		&cli.StringFlag{
			Name:     "idp-id",
			Aliases:  []string{"i"},
			Usage:    "Google SP identifier",
			Required: true,
			EnvVars:  []string{"GOOGLE_IDP_ID"},
		},
		&cli.StringFlag{
			Name:    "role-arn",
			Aliases: []string{"r"},
			Usage:   "AWS Role Arn for assuming to",
		},
		&cli.StringFlag{
			Name:  "saml-file",
			Usage: "Path to file contains SAML Assertion",
			Value: "~/.aws_google_login_cache.txt",
		},
		&cli.BoolFlag{
			Name:  "no-cache",
			Usage: "Force to re-authenticate",
			Value: false,
		},
		&cli.BoolFlag{
			Name:  "get-saml-assertion",
			Usage: "Getting SAML assertion XML",
			Value: false,
		},
		&cli.BoolFlag{
			Name:  "export",
			Usage: "Print export line for working with aws cli",
			Value: false,
		},
	}

	err := app.Run(os.Args)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
