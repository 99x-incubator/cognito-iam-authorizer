const jwt = require('jsonwebtoken');
const aws = require('aws-sdk');
const _ = require('lodash');
const async = require('async');

'use strict';

console.log('Loading function');

AwsCustomAuthoriserPolicyBuilder.buildPolicy = (jwtIdToken, callback) => {

    let authToken = jwtIdToken;
    let iam = new aws.IAM();
    let decodedJwt = jwt.decode(authToken);

    console.log(decodedJwt);

    let roleNames = _.map(decodedJwt["cognito:roles"], function (arn) {
        return _.last(arn.split('/'));
    });

    let getPolicyNames = function (roleName, callback) {
        iam.listRolePolicies({ RoleName: roleName }, function (err, data) {
            var policyNames = data["PolicyNames"];
            callback(null, policyNames);
        });
    };

    let getPolicyDocumentRequets = function (policyNames, roleName, callback) {
        let getPolicyDocument = function (policyName, roleName, callback) {
            iam.getRolePolicy({ PolicyName: policyName, RoleName: roleName }, function (err, data) {
                callback(null, decodeURIComponent(data["PolicyDocument"]));
            });
        };
        return _.map(policyNames, function (policyName) {
            return function (callback) {
                getPolicyDocument(policyName, roleName, callback);
            };
        });
    };

    let buildReturnPolicyDocument = function (policyDocuments) {
        var policyDocument = {};

        let statement = _.flatMap(policyDocuments, function (policyDocument) {
            policyDocumentObj = JSON.parse(policyDocument);
            return policyDocumentObj.Statement
        });

        policyDocument.Version = "2012-10-17";
        policyDocument.Statement = statement;

        console.log(statement);
        return policyDocument;
    };

    let iamPolicyDocumentRequests = _.map(roleNames, function (roleName) {
        return function (callback) {
            async.waterfall([
                function (callback) {
                    console.log('get roleName', roleName);
                    getPolicyNames(roleName, callback);
                }, function (policyNames, callback) {
                    let policyDocumentRequests = getPolicyDocumentRequets(policyNames, roleName, callback);
                    async.parallel(policyDocumentRequests, function (err, policyDocuments) {
                        console.log('get documents', policyDocuments);
                        callback(null, policyDocuments);
                    });
                },
            ], function (err, policyDocuments) {
                callback(null, policyDocuments);
            });
        };
    });

    async.parallel(iamPolicyDocumentRequests, function (err, policyDocumentsNested) {
        let policyDocument = buildReturnPolicyDocument(_.flatten(policyDocumentsNested));
        let returnPolicy = {};

        returnPolicy.principalId = decodedJwt["cognito:roles"][0];
        returnPolicy.policyDocument = policyDocument;

        callback(null, returnPolicy);
    });
};

module.exports = AwsCustomAuthoriserPolicyBuilder;