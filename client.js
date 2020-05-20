const express = require('express');
const bodyParser = require('body-parser');
const request = require('sync-request');
const url = require('url');
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
  redirect_uris: ['http://localhost:9000/callback'],
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
const wordApi = 'http://localhost:9002/words';

const state = null;

let accessToken = null;
let refreshToken = null;
let scope = null;

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
 * Route HTTP POST request to server root.
 */
app.post('/login', (req, res) => {
  const { username } = req.body;
  const { password } = req.body;

  const form_data = qs.stringify({
    grant_type: 'password',
    username,
    password,
    scope: client.scope,
  });

  const headers = {
    'Content-Type': 'application/x-www-form-urlencoded',
    Authorization: `Basic ${encodeClientCredentials(client.client_id, client.client_secret)}`,
  };

  const tokRes = request('POST', authServer.token_endpoint, {
    body: form_data,
    headers,
  });

  if (tokRes.statusCode >= 200 && tokRes.statusCode < 300) {
    const body = JSON.parse(tokRes.getBody());

    accessToken = body.access_token;

    scope = body.scope;

    refreshToken = body.refresh_token;

    res.render('index', { access_token: accessToken, refresh_token: refreshToken, scope });
  } else {
    res.render('error', { error: `Unable to fetch access token, server response: ${tokRes.statusCode}` });
  }
});

app.get('/callback', (req, res) => {
  if (req.query.error) {
    // it's an error response, act accordingly
    res.render('error', { error: req.query.error });
    return;
  }

  const resState = req.query.state;
  if (resState == state) {
    console.log('State value matches: expected %s got %s', state, resState);
  } else {
    console.log('State DOES NOT MATCH: expected %s got %s', state, resState);
    res.render('error', { error: 'State value did not match' });
    return;
  }

  const { code } = req.query;

  const form_data = qs.stringify({
    grant_type: 'authorization_code',
    code,
    redirect_uri: client.redirect_uris[0],
  });
  const headers = {
    'Content-Type': 'application/x-www-form-urlencoded',
    Authorization: `Basic ${encodeClientCredentials(client.client_id, client.client_secret)}`,
  };

  const tokRes = request('POST', authServer.token_endpoint,
    {
      body: form_data,
      headers,
    });

  console.log('Requesting access token for code %s', code);

  if (tokRes.statusCode >= 200 && tokRes.statusCode < 300) {
    const body = JSON.parse(tokRes.getBody());

    accessToken = body.access_token;
    console.log('Got access token: %s', accessToken);
    if (body.refresh_token) {
      refreshToken = body.refresh_token;
      console.log('Got refresh token: %s', refreshToken);
    }

    scope = body.scope;
    console.log('Got scope: %s', scope);

    res.render('index', { access_token: accessToken, refresh_token: refreshToken, scope });
  } else {
    res.render('error', { error: `Unable to fetch access token, server response: ${tokRes.statusCode}` });
  }
});

app.post('/revoke', (req, res) => {
  const form_data = qs.stringify({
    token: refreshToken,
  });
  const headers = {
    'Content-Type': 'application/x-www-form-urlencoded',
    Authorization: `Basic ${encodeClientCredentials(client.client_id, client.client_secret)}`,
  };
  console.log('Revoking token %s', refreshToken);
  const tokRes = request('POST', authServer.revocation_endpoint, {
    body: form_data,
    headers,
  });

  accessToken = null;
  refreshToken = null;
  scope = null;

  if (tokRes.statusCode >= 200 && tokRes.statusCode < 300) {
    res.render('index', { access_token: accessToken, refresh_token: refreshToken, scope });
  } else {
    res.render('error', { error: tokRes.statusCode });
  }
});

app.get('/words', (req, res) => {
  res.render('words', { word: '', position: -1, result: '' });
});

app.get('/get_word', (req, res) => {
  const headers = {
    Authorization: `Bearer ${accessToken}`,
    'Content-Type': 'application/x-www-form-urlencoded',
  };

  const resource = request('GET', wordApi,
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

app.get('/add_word', (req, res) => {
  const headers = {
    Authorization: `Bearer ${accessToken}`,
    'Content-Type': 'application/x-www-form-urlencoded',
  };

  const form_body = qs.stringify({ word: req.query.word });

  const resource = request('POST', wordApi,
    { headers, body: form_body });

  if (resource.statusCode >= 200 && resource.statusCode < 300) {
    const body = JSON.parse(resource.getBody());
    res.render('words', { word: body.word, position: body.position, result: 'add' });
  } else if (resource.statusCode === 401 || resource.statusCode === 403) {
    res.render('error', { error: `Server returned response code: ${resource.statusCode}` });
  } else {
    res.render('words', { word: '', position: -1, result: 'noadd' });
  }
});

app.get('/delete_word', (req, res) => {
  const headers = {
    Authorization: `Bearer ${accessToken}`,
    'Content-Type': 'application/x-www-form-urlencoded',
  };

  const resource = request('DELETE', wordApi,
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


app.use('/', express.static('files/client'));

const buildUrl = function (base, options, hash) {
  const newUrl = url.parse(base, true);
  delete newUrl.search;
  if (!newUrl.query) {
    newUrl.query = {};
  }
  __.each(options, (value, key, list) => {
    newUrl.query[key] = value;
  });
  if (hash) {
    newUrl.hash = hash;
  }

  return url.format(newUrl);
};

var encodeClientCredentials = function (clientId, clientSecret) {
  return new Buffer.from(`${querystring.escape(clientId)}:${querystring.escape(clientSecret)}`).toString('base64');
};

var server = app.listen(9000, 'localhost', () => {
  const host = server.address().address;
  const { port } = server.address();
  console.log('OAuth Client listening at http://%s:%s', host, port);
});
