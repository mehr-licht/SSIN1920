const express = require('express');
const bodyParser = require('body-parser');
const request = require('sync-request');
const qs = require('qs');
const querystring = require('querystring');
const cons = require('consolidate');
// eslint-disable-next-line no-underscore-dangle
const __ = require('underscore');
__.string = require('underscore.string');


/**
 * Set Express web application.
 * @type {app}
 */
const app = express();

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

app.engine('html', cons.underscore);
app.set('view engine', 'html');
app.set('views', 'files/client');

/**
 * Client information.
 */
const client = {
  client_id: 'oauth-client',
  client_secret: 'oauth-client-secret',
  scope: 'read write delete',
};

/**
 * Authorization server information for authorization.
 */
const authServer = {
  authorization_endpoint: 'http://localhost:9001/authorize',
  token_endpoint: 'http://localhost:9001/token',
  revocation_endpoint: 'http://localhost:9001/revoke',
};

/**
 * Words API resource endpoint.
 */
const wordApiEndpoint = 'http://localhost:9002/words';

let accessToken = null;
let refreshToken = null;
let scope = null;


/**
 * Encode credentials sent to the authorization server.
 *
 * @param clientId
 * @param clientSecret
 * @returns {string}
 */
const encodeClientCredentials = (clientId, clientSecret) => Buffer.from(`${querystring.escape(clientId)}:${querystring.escape(clientSecret)}`).toString('base64');

/**
 * Route HTTP GET request to client root.
 */
app.get('/', (req, res) => {
  res.render('index', { access_token: accessToken, refresh_token: refreshToken, scope });
});


/**
 * Route HTTP GET request to the login form.
 */
app.get('/authorize', (req, res) => {
  res.render('login');
});

/**
 * Route HTTP POST request to obtain a token from authorization server.
 */
app.post('/login', (req, res) => {
  const { username } = req.body;
  const { password } = req.body;

  const formData = qs.stringify({
    grant_type: 'password',
    username,
    password,
    scope: client.scope,
  });

  const headers = {
    'Content-Type': 'application/x-www-form-urlencoded',
    Authorization: `Basic ${encodeClientCredentials(client.client_id, client.client_secret)}`,
  };

  const tokenResponse = request('POST', authServer.token_endpoint, {
    body: formData,
    headers,
  });

  if (tokenResponse.statusCode >= 200 && tokenResponse.statusCode < 300) {
    const body = JSON.parse(tokenResponse.getBody());

    accessToken = body.access_token;

    scope = body.scope;

    refreshToken = body.refresh_token;

    res.render('index', { access_token: accessToken, refresh_token: refreshToken, scope });
  } else {
    res.render('error', { error: `Unable to fetch access token, server response: ${tokenResponse.statusCode}` });
  }
});

/**
 * Route HTTP POST request to revoke tokens on the authorization server.
 */
app.post('/revoke', (req, res) => {
  const formData = qs.stringify({
    token: refreshToken,
  });
  const headers = {
    'Content-Type': 'application/x-www-form-urlencoded',
    Authorization: `Basic ${encodeClientCredentials(client.client_id, client.client_secret)}`,
  };
  console.log('Revoking token %s', refreshToken);
  const tokenResponse = request('POST', authServer.revocation_endpoint, {
    body: formData,
    headers,
  });

  accessToken = null;
  refreshToken = null;
  scope = null;

  if (tokenResponse.statusCode >= 200 && tokenResponse.statusCode < 300) {
    res.render('index', { access_token: accessToken, refresh_token: refreshToken, scope });
  } else {
    res.render('error', { error: tokenResponse.statusCode });
  }
});

/**
 * Route HTTP GET request to Words API (Protected Resource).
 */
app.get('/words', (req, res) => {
  res.render('words', { word: '', position: -1, result: '' });
});

/**
 * Route HTTP GET request to obtain a word from Words API (Protected Resource).
 */
app.get('/get_word', (req, res) => {
  const headers = {
    Authorization: `Bearer ${accessToken}`,
    'Content-Type': 'application/x-www-form-urlencoded',
  };

  const resource = request('GET', wordApiEndpoint,
    { headers, qs: req.query });

  if (resource.statusCode >= 200 && resource.statusCode < 300) {
    const body = JSON.parse(resource.getBody());
    res.render('words', { word: body.word, position: body.position, result: body.result });
  } else if (resource.statusCode === 401 || resource.statusCode === 403) {
    res.render('error', { error: `Server returned response code: ${resource.statusCode}` });
  } else {
    res.render('words', { word: '', position: -1, result: 'noget' });
  }
});

/**
 * Route HTTP GET request to add a word to Words API (Protected Resource).
 */
app.get('/add_word', (req, res) => {
  const headers = {
    Authorization: `Bearer ${accessToken}`,
    'Content-Type': 'application/x-www-form-urlencoded',
  };

  const formBody = qs.stringify({ word: req.query.word });

  const resource = request('POST', wordApiEndpoint,
    { headers, body: formBody });

  if (resource.statusCode >= 200 && resource.statusCode < 300) {
    const body = JSON.parse(resource.getBody());
    res.render('words', { word: body.word, position: body.position, result: 'add' });
  } else if (resource.statusCode === 401 || resource.statusCode === 403) {
    res.render('error', { error: `Server returned response code: ${resource.statusCode}` });
  } else {
    res.render('words', { word: '', position: -1, result: 'noadd' });
  }
});

/**
 * Route HTTP GET request to delete a word from Words API (Protected Resource).
 */
app.get('/delete_word', (req, res) => {
  const headers = {
    Authorization: `Bearer ${accessToken}`,
    'Content-Type': 'application/x-www-form-urlencoded',
  };

  const resource = request('DELETE', wordApiEndpoint,
    { headers, qs: req.query });

  if (resource.statusCode >= 200 && resource.statusCode < 300) {
    const body = JSON.parse(resource.getBody());
    res.render('words', { word: body.word, position: body.position, result: body.result });
  } else if (resource.statusCode === 401 || resource.statusCode === 403) {
    res.render('error', { error: `Server returned response code: ${resource.statusCode}` });
  } else {
    res.render('words', { word: '', position: -1, result: 'norm' });
  }
});


/**
 * Middleware function mount point for server.
 */
app.use('/', express.static('files/client'));

/**
 * Set Express web application listening port.
 */
const server = app.listen(9000, 'localhost', () => {
  const host = server.address().address;
  const { port } = server.address();

  console.log('OAuth Client listening at http://%s:%s', host, port);
});
