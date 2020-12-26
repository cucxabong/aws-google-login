package main

import (
	"fmt"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
)

const DEFAULT_SESSION_DURATION = 3600

type Amazon struct {
	SamlAssertion   string
	SessionDuration int64
}

func NewAmazonConfig(samlAssertion string, sessionDuration int64) *Amazon {
	return &Amazon{
		SamlAssertion:   samlAssertion,
		SessionDuration: sessionDuration,
	}
}

func (amz *Amazon) GetAssertion() string {
	return amz.SamlAssertion
}

// GetRoleAttrName return XML attribute name for Role property
func (*Amazon) GetRoleAttrName() string {
	return "https://aws.amazon.com/SAML/Attributes/Role"
}

// GetRoleSessionNameAttrName return XML attribute name for RoleSessionName property
func (*Amazon) GetRoleSessionNameAttrName() string {
	return "https://aws.amazon.com/SAML/Attributes/RoleSessionName"
}

// GetSessionDurationAttrName return XML attribute name for SessionDuration property
func (*Amazon) GetSessionDurationAttrName() string {
	return "https://aws.amazon.com/SAML/Attributes/SessionDuration"
}

// AssumeRole is going to call sts.AssumeRoleWithSAMLInput to assume to a specific role
func (amz *Amazon) AssumeRole(roleArn, principalArn string) (*sts.Credentials, error) {
	svc := sts.New(session.New())
	input := &sts.AssumeRoleWithSAMLInput{
		DurationSeconds: aws.Int64(amz.SessionDuration),
		PrincipalArn:    aws.String(principalArn),
		RoleArn:         aws.String(roleArn),
		SAMLAssertion:   aws.String(amz.SamlAssertion),
	}

	result, err := svc.AssumeRoleWithSAML(input)
	if err != nil {
		return nil, fmt.Errorf("unable to assume role %v\n", err)
	}

	return result.Credentials, nil
}
