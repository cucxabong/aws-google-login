package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"text/template"

	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/urfave/cli/v2"
)

type Option struct {
	spID     string
	idpID    string
	Duration int64
	ListRole bool
	SamlFile string
	NoCache  bool
	RoleArn  string
}

func parseOption(c *cli.Context) (*Option, error) {
	opt := &Option{}

	opt.spID = c.String("sp-id")
	opt.idpID = c.String("idp-id")
	opt.Duration = c.Int64("duration")
	opt.ListRole = c.Bool("list-roles")
	opt.SamlFile = c.String("saml-file")
	opt.NoCache = c.Bool("no-cache")
	if c.IsSet("role-arn") {
		opt.RoleArn = c.String("role-arn")
	}

	if strings.HasPrefix(opt.SamlFile, "~/") {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return nil, err
		}
		opt.SamlFile = filepath.Join(homeDir, strings.TrimPrefix(opt.SamlFile, "~/"))
	}

	return opt, nil
}

func writeSamlAssertion(filename, assertion string) error {
	return ioutil.WriteFile(filename, []byte(assertion), 0600)
}

func handler(c *cli.Context) error {
	var roleArn, assertion string
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
			if IsValidSamlAssertion(string(data)) {
				assertion = string(data)
			}
		}
	}

	if assertion == "" {
		g := NewGoogleConfig(opt.idpID, opt.spID)
		assertion, err = g.Login()
		if err != nil {
			return err
		}
		writeSamlAssertion(opt.SamlFile, assertion)
	}

	amz := NewAmazonConfig(assertion, opt.Duration)

	if opt.ListRole {
		return listRolesHandler(amz)
	}

	if roleArn != "" {
		return assumeSingleRoleHandler(amz, roleArn)
	}

	return interactiveAssumeRole(amz)
}

func printExportline(stsCred *sts.Credentials) error {
	t := template.Must(template.New("aws-export-line").Parse(AWS_CREDS_EXPORT_TEMPLATE))
	return t.Execute(os.Stdout, stsCred)
}

func GetAssociatedRoles(amz *Amazon) ([]string, error) {
	resp := []string{}
	samlRoles, err := GetAttributeValuesFromAssertion(amz.GetAssertion(), amz.GetRoleAttrName())
	if err != nil {
		return resp, err
	}

	for _, v := range samlRoles {
		resp = append(resp, GetRoleArnFromSAMLRole(v))
	}

	return resp, nil
}

func assumeSingleRoleHandler(amz *Amazon, roleArn string) error {
	var principalArn string
	samlRoles, err := GetAttributeValuesFromAssertion(amz.GetAssertion(), amz.GetRoleAttrName())
	if err != nil {
		return err
	}

	for _, v := range samlRoles {
		if roleArn == GetRoleArnFromSAMLRole(v) {
			principalArn = GetPrincipalArnFromSAMLRole(v)
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
	err = printExportline(stsCreds)
	if err != nil {
		return fmt.Errorf("unable to render export line %v", err)
	}
	fmt.Printf("Credentials Expiration: %q\n", stsCreds.Expiration.String())

	return nil
}

func listRolesHandler(amz *Amazon) error {
	roles, err := GetAssociatedRoles(amz)
	if err != nil {
		return err
	}
	for _, v := range roles {
		fmt.Println(v)
	}

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
			Value:   DEFAULT_SESSION_DURATION,
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
			Value: "~/.awssaml_cache.cfg",
		},
		&cli.BoolFlag{
			Name:  "no-cache",
			Usage: "Force to re-authenticate",
			Value: false,
		},
	}

	err := app.Run(os.Args)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
