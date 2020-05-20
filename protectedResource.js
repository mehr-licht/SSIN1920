const express = require('express');
const bodyParser = require('body-parser');
const cons = require('consolidate');
const qs = require('qs');
const querystring = require('querystring');
const request = require('sync-request');
// eslint-disable-next-line no-underscore-dangle
const __ = require('underscore');
const cors = require('cors');

/**
 * Set Express web application.
 * @type {app}
 */
const app = express();

app.use(bodyParser.urlencoded({ extended: true }));

app.engine('html', cons.underscore);
app.set('view engine', 'html');
app.set('views', 'files/protectedResource');
app.set('json spaces', 4);

/**
 * Middleware function mount point for server.
 */
app.use('/', express.static('files/protectedResource'));

/**
 * Enable All CORS Requests.
 */
app.use(cors());

/**
 * Protected resource information.
 */
const protectedResources = {
  resource_id: 'protected-resource',
  resource_secret: 'protected-resource-secret',
};

/**
 * Authorization server information for introspection.
 */
const authServer = {
  introspectionEndpoint: 'http://localhost:9001/introspect',
};

/**
 * Get the access token from the HTTP headers.
 * @param req
 * @param res
 * @param next
 */
const getAccessToken = (req, res, next) => {
  const auth = req.headers.authorization;
  let token = null;

  if (auth && auth.toLowerCase().indexOf('bearer') === 0) {
    token = auth.slice('bearer '.length);
  } else if (req.body && req.body.access_token) {
    token = req.body.access_token;
  } else if (req.query && req.query.access_token) {
    token = req.query.access_token;
  }

  console.log('Incoming token: %s', token);

  const formData = qs.stringify({ token });

  const headers = {
    'Content-Type': 'application/x-www-form-urlencoded',
    Authorization: `Basic ${Buffer.from(`${querystring.escape(protectedResources.resource_id)}:${querystring.escape(protectedResources.resource_secret)}`).toString('base64')}`,
  };

  const introspectionResponse = request('POST', authServer.introspectionEndpoint,
    {
      body: formData,
      headers,
    });

  if (introspectionResponse.statusCode >= 200 && introspectionResponse.statusCode < 300) {
    const body = JSON.parse(introspectionResponse.getBody());

    console.log('Introspection response: ', body);
    const { active } = body;
    if (active) {
      req.access_token = body;
    }
  }
  next();
};

const requireAccessToken = function (req, res, next) {
  if (req.access_token) {
    next();
  } else {
    res.status(401).end();
  }
};

const savedWords = [];

app.get('/words', getAccessToken, requireAccessToken, (req, res) => {
  if (__.contains(req.access_token.scope.split(' '), 'read')) {
    const position = savedWords.indexOf(req.query.word);
    if (position >= 0) {
      res.json({ word: req.query.word, position, result: 'get' });
    } else {
      res.json({ word: req.query.word, position: -1, result: 'noget' });
    }
  } else {
    res.set('WWW-Authenticate', 'Bearer realm=localhost:9002, error="insufficient_scope", scope="read"'); // see rfc6750
    res.status(403).json({ error: 'insufficient_scope' });
  }
});

app.post('/words', getAccessToken, requireAccessToken, (req, res) => {
  if (__.contains(req.access_token.scope.split(' '), 'write')) {
    if (req.body.word) {
      savedWords.push(req.body.word);
      const position = savedWords.indexOf(req.body.word);
      res.json({ word: req.body.word, position, result: 'add' });
      res.status(201).end();
    } else {
      res.json({ word: req.body.word, position: -1, result: 'noadd' });
    }
  } else {
    res.set('WWW-Authenticate', 'Bearer realm=localhost:9002, error="insufficient_scope", scope="write"');
    res.status(403).json({ error: 'insufficient_scope' });
  }
});

app.delete('/words', getAccessToken, requireAccessToken, (req, res) => {
  if (__.contains(req.access_token.scope.split(' '), 'delete')) {
    const position = savedWords.indexOf(req.query.word);
    if (position >= 0) {
      res.json({ word: req.query.word, position, result: 'rm' });
      savedWords.pop();
      res.status(201).end();
    } else {
      res.json({ word: req.query.word, position: -1, result: 'norm' });
    }
  } else {
    res.set('WWW-Authenticate', 'Bearer realm=localhost:9002, error="insufficient_scope", scope="delete"');
    res.status(403).json({ error: 'insufficient_scope' });
  }
});

/**
 * Set Express web application listening port.
 */
const server = app.listen(9002, 'localhost', () => {
  const host = server.address().address;
  const { port } = server.address();

  console.log('OAuth Resource Server listening at http://%s:%s', host, port);
});
