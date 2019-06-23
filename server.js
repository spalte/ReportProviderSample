const http = require('http');
const syncRequest = require('sync-request');
const url = require('url');
const fs = require('fs')
const pem2jwk = require('pem-jwk').pem2jwk;
const request = require('request');
const jwt = require('jsonwebtoken');

const myIP = '192.168.1.157'
const listenPort = 80

let instrospect = function(token, endpoint) {
  request.post(endpoint, {
    form: {
        token: token
    }},
    function(err, httpResponse, body) {
      const introspection = JSON.parse(body);
      console.log('introspection:\n' + JSON.stringify(introspection, null, 4));
    });
}

var app = http.createServer(function(req,res){
    const pem = fs.readFileSync('./key.pem', 'ascii')

    console.log("serving...")

    const requestURL = url.parse(req.url, true);
    const pathname = requestURL.pathname;
    if (pathname == "/cert") {
        console.log("cert");

        const fulljwk = pem2jwk(pem);
        let jwk = {};
        jwk.n = fulljwk.n;
        jwk.e = fulljwk.e;
        jwk.kid = '0';
        jwk.kty = 'RSA'
        jwk.alg = 'RSA256'
        jwk.use = 'sig'

        res.setHeader('Content-Type', 'application/json');
        res.end(JSON.stringify({keys: [jwk]}));
    } else if (pathname == "/report") {
        console.log("report");

        const query = requestURL.query;

        const code = query['code'];

        if (!code) {

          // instrospect(tokenResponse.access_token, kheopsConfig.instrospection_endpoint);

            const implicitHTML = 
            `
            <!doctype html>
            <html>
              <head>
                <title>This is the title of the webpage!</title>
              </head>
              <body>
                <p>Web Page with implicit flow</p>
              </body>
            </html>
            `;

            res.setHeader('Content-Type', 'text/html');
            res.end(implicitHTML);        
            return;
        }

        const conf_uri = query['conf_uri'];
        const studyInstanceUID = query['studyUID'];
        const clientID = query['client_id'];
        const returnURI = query['return_uri'];

        const configURL = url.parse(conf_uri);

        console.log("code:" + code);
        console.log("conf_uri:" + conf_uri);
        console.log("studyInstanceUID:" + studyInstanceUID);
        console.log("clientID:" + clientID);
        console.log("returnURI:" + returnURI);

        const kheopsConfig = JSON.parse(syncRequest('GET', conf_uri).getBody())

        console.log('kheopsConfig:\n' + JSON.stringify(kheopsConfig, null, 4));

        const clientJWT = jwt.sign({
        }, pem, {
            algorithm: 'RS256',
            issuer: clientID,
            subject: clientID,
            audience: `${configURL.protocol}//${configURL.host}/api/token`,
            jwtid: Math.floor(Math.random() * 1000000000).toString(),
            keyid: '0',
            expiresIn: 120,
        });

        console.log('clientJWT: ' + clientJWT);

        request.post(kheopsConfig.token_endpoint, {
            form: {
                grant_type: 'authorization_code',
                code: code,
                client_id: clientID,
                client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
                client_assertion: clientJWT,
                redirect_uri: `http://${myIP}/report`,
            }},
            function(err, httpResponse, body) {
                if (err) {
                    res.setHeader('Content-Type', 'text/plain');
                    res.end("error");            
                }

                const tokenResponse = JSON.parse(body);

                console.log('response:\n' + JSON.stringify(tokenResponse, null, 4));

                instrospect(tokenResponse.access_token, kheopsConfig.introspection_endpoint);

                const userInfo = JSON.parse(syncRequest('GET', kheopsConfig.userinfo_endpoint, {
                    'headers': {
                        'authorization': 'Bearer ' + tokenResponse.access_token
                    }
                }).getBody());

                const search = JSON.parse(syncRequest('GET', `${kheopsConfig.dicomweb_endpoint}/studies?includefield=00081030`, {
                    'headers': {
                        'authorization': 'Bearer ' + tokenResponse.access_token
                    }
                }).getBody());

                const responseHTML = 
                `
                <!doctype html>
                <html>
                  <head>
                    <title>This is the title of the webpage!</title>
                  </head>
                  <body>
                    <p>User with email address ${userInfo.email} is accessing the study ${search[0]['00081030']['Value'][0]}</p>
                    <p><a href="${returnURI}">return</a></p>
                  </body>
                </html>
                `;

                res.setHeader('Content-Type', 'text/html');
                res.end(responseHTML);        
            });    


    } else {
        console.log("configuration");

        let object = {
            jwks_uri: `http://${myIP}/cert`,
            token_endpoint_auth_method: 'private_key_jwt',
            token_endpoint_auth_signing_alg: 'RS256',
            redirect_uri: `http://${myIP}/report`,
            response_type: 'code',
        }

        res.setHeader('Content-Type', 'application/json');
        res.end(JSON.stringify(object));
    }
});
app.listen(listenPort);
