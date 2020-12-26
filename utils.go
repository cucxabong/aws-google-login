package main

import (
	"strings"
	"time"

	"github.com/RobotsAndPencils/go-saml"
)

func IsValidSamlAssertion(assertion string) bool {
	if len(assertion) == 0 {
		return false
	}

	parsedSaml, err := saml.ParseEncodedResponse(assertion)
	if err != nil {
		panic(err)
	}

	notBefore, err := time.Parse(time.RFC3339Nano, parsedSaml.Assertion.Conditions.NotBefore)
	if err != nil {
		panic(err)
	}
	notOnOrAfter, err := time.Parse(time.RFC3339Nano, parsedSaml.Assertion.Conditions.NotOnOrAfter)
	if err != nil {
		panic(err)
	}
	now := time.Now()

	if now.Before(notBefore) || now.After(notOnOrAfter) || now.Equal(notOnOrAfter) {
		return false
	}

	return true
}

// GetAttributeValuesFromAssertion parse SAML Assertion in form of XML document
// to return a list of attribute values from attribute name
func GetAttributeValuesFromAssertion(assertion, attributeName string) ([]string, error) {
	parsedSaml, err := saml.ParseEncodedResponse(assertion)
	if err != nil {
		return nil, err
	}

	return parsedSaml.GetAttributeValues(attributeName), nil
}

func getArnFromSamlRoleAttribute(samlRole string, idx uint) string {
	return strings.Trim(strings.Split(samlRole, ",")[idx], " ")
}

// GetRoleArnFromSAMLRole pase a SAML role string in form of "[ROLE_ARN],[PROVIDER_ARN]"
// and return the first part of the input (a valid AWS IAM Role ARN)
func GetRoleArnFromSAMLRole(samlRole string) string {
	return getArnFromSamlRoleAttribute(samlRole, 0)
}

// GetRoleArnFromSAMLRole pase a SAML role string in form of "[ROLE_ARN],[PROVIDER_ARN]"
// and return the second part of the input (a valid AWS IAM Provider ARN)
func GetPrincipalArnFromSAMLRole(samlRole string) string {
	return getArnFromSamlRoleAttribute(samlRole, 1)
}

// func getListArnFromSamlRoleAttribute(assertionDocs, samlRoleAttrName string, idx uint) ([]string, error) {
// 	resp := []string{}
// 	parsedSaml, err := saml.ParseEncodedResponse(assertionDocs)
// 	if err != nil {
// 		return resp, fmt.Errorf("unable to parse SAML assertion document %v\n", err)
// 	}

// 	roles := parsedSaml.GetAttributeValues(samlRoleAttrName)
// 	for _, v := range roles {
// 		resp = append(resp, getArnFromSamlRoleAttribute(v, idx))
// 	}

// 	return resp, nil
// }

// func RolesFromSAMLAssertion(assertionDocs, samlRoleAttrName string) ([]string, error) {
// 	return getListArnFromSamlRoleAttribute(assertionDocs, samlRoleAttrName, 0)
// }

// func PrincipalsFromSAMLAssertion(assertionDocs, samlRoleAttrName string) ([]string, error) {
// 	return getListArnFromSamlRoleAttribute(assertionDocs, samlRoleAttrName, 1)
// }

// func profileNameFromArn(s string) (string, error) {
// 	parsedArn, err := arn.Parse(s)
// 	if err != nil {
// 		return "", fmt.Errorf("invalid arn string %v", err)
// 	}

// 	return fmt.Sprintf("%s-%s", parsedArn.AccountID, strings.Split(parsedArn.Resource, "/")[1]), nil
// }

// func jsonOutput(v interface{}, w io.Writer) error {
// 	jsonData, err := json.Marshal(v)
// 	if err != nil {
// 		return err
// 	}
// 	_, err = fmt.Fprint(w, string(jsonData))
// 	return err
// }

// func normalOutput(v interface{}, w io.Writer) error {
// 	_, err := fmt.Fprint(w, v)
// 	return err
// }

// func awsCredsRender(profiles []*AWSProfileEntry) error {
// 	tmpl := `
// {{- range . }}
// [{{.Name}}]
// aws_access_key_id = {{ .AccessKeyId }}
// aws_secret_access_key = {{ .SecretAccessKey }}
// aws_session_token = {{ .SessionToken }}
// {{- end }}
// 	`
// 	t := template.Must(template.New("awsProfile").Parse(tmpl))
// 	return t.Execute(os.Stdout, profiles)
// }
