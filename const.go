package main

var AWS_CREDS_EXPORT_TEMPLATE = `
export AWS_ACCESS_KEY_ID={{ .AccessKeyId }}
export AWS_SESSION_TOKEN={{ .SessionToken }}
export AWS_SECRET_ACCESS_KEY={{ .SecretAccessKey }}

`
