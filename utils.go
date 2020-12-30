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
