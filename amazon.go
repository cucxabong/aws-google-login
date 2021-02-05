package awslogin

import (
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
)

const DEFAULT_SESSION_DURATION = 3600

type Amazon struct {
	SamlAssertion   string
	SessionDuration int64
}

type Role struct {
	RoleArn      string `json:"role_arn"`
	PrincipalArn string `json:"principal_arn"`
}

func (r *Role) String() string {
	return r.RoleArn
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

func (amz *Amazon) parseRole(role string) (*Role, error) {
	items := strings.Split(role, ",")
	if len(items) != 2 {
		return nil, fmt.Errorf("invalid role string %v\n", role)
	}

	return &Role{
		RoleArn:      items[0],
		PrincipalArn: items[1],
	}, nil
}

func (amz *Amazon) ParseRoles() ([]*Role, error) {
	resp := []*Role{}
	roleValues, err := GetAttributeValuesFromAssertion(amz.GetAssertion(), amz.GetRoleAttrName())
	if err != nil {
		return nil, err
	}

	for _, v := range roleValues {
		role, err := amz.parseRole(v)
		if err != nil {
			return nil, err
		}

		resp = append(resp, role)
	}

	return resp, nil
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

// AssumeRole is going to call sts.AssumeRoleWithSAML to assume to a specific role
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
