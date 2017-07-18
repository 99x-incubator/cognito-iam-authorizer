# cognito-iam-authorizer

Cognito IAM Authorizer which authenticates Cognito JWT token and attach Cognito UserPool User Groups Permission to invoke API Gateway.

It is ideal to be used in a AWS Lambda function since it has been optimised to fetch roles and policies parallely. It also provides a method to validate the ID Token that is sent by Cognito after the user has been validated.

## Installation

## Usage

```
const CognitoIamAuthoriser = require("cognito-iam-authoriser")

CognitoIamAuthoriser.validateCognitoIdToken(idToken, pemFileObj, iss, function (err, message) {
        if (!err) {
            console.log("Token validated successfully..");
            CognitoIamAuthoriser.buildPolicyFromIam(idToken, function (err, policyDocument) {
                if (policyDocument) {
                    callback(null, policyDocument)
                }
                else {
                    callback(err);
                }
            });
        }
        else {
            callback(err);
        }
    });
```

## Contributing