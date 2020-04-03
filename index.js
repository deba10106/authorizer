// A simple token-based authorizer example to demonstrate how to use an authorization token
// to allow or deny a request. In this example, the caller named 'user' is allowed to invoke
// a request if the client-supplied token value is 'allow'. The caller is not allowed to invoke
// the request if the token value is 'deny'. If the token value is 'unauthorized' or an empty
// string, the authorizer function returns an HTTP 401 status code. For any other token value,
// the authorizer returns an HTTP 500 status code.
// Note that token values are case-sensitive.
const axios = require('axios');
const BACKEND_HOST = process.env.BACKEND_HOST;

exports.handler =  async function(event, context, callback) {
    var token = event.authorizationToken ;
    let userResponse = await axios.get(`${BACKEND_HOST}/user/token`, {
      headers: {
        authorization: `${token}`,
      },
    });

    let contextResp = {};
    contextResp = userResponse.data;
    if (userResponse.status === 200) {
      callback(null, generatePolicy('user', 'Allow', event.methodArn, contextResp));
    }else {
      callback("Unauthorized");
    }

};

// Help function to generate an IAM policy
function generatePolicy(principalId, effect, resource, context) {
    var authResponse = {};

    authResponse.principalId = principalId;
    if (effect && resource) {
        var policyDocument = {};
        policyDocument.Version = '2012-10-17';
        policyDocument.Statement = [];
        var statementOne = {};
        statementOne.Action = 'execute-api:Invoke';
        statementOne.Effect = effect;
        statementOne.Resource = resource;
        policyDocument.Statement[0] = statementOne;
        authResponse.policyDocument = policyDocument;
        authResponse.context = context;
    }
    return authResponse;
}
