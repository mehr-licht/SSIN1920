const express = require('express');
const bodyParser = require('body-parser');
const randomstring = require('randomstring');
const cons = require('consolidate');
const Datastore = require('nedb');

const
  tokenDb = new Datastore({ filename: './tokens.nedb', autoload: true });

const
  usersDb = new Datastore({ filename: './users.nedb', autoload: true });
const querystring = require('querystring');
// eslint-disable-next-line no-underscore-dangle
const __ = require('underscore');
__.string = require('underscore.string');


/**
 * Set Express web application
 * @type {app}
 */
const app = express();

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

app.engine('html', cons.underscore);
app.set('view engine', 'html');
app.set('views', 'files/authorizationServer');
app.set('json spaces', 4);

/**
 * Init Users database in case it does not exist
 */
usersDb.count({}, (err, count) => {
  if (!count) {
    usersDb.insert(
      [
        { username: 'alice', password: 'password', scope: 'read write delete' },
        { username: 'bob', password: '123456', scope: 'read' },
        { username: 'chuck', password: 'qwerty', scope: 'write delete' },
        { username: 'eve', password: '1q2w3e4r', scope: '' },
      ], (errInsert) => {
        if (errInsert) {
          console.error(errInsert);
        }
      },
    );
  }
  if (err) {
    console.error(err);
  }
});

/**
 * Authorization server information
 */
const authServer = {
  authorizationEndpoint: 'http://localhost:9001/authorize',
  tokenEndpoint: 'http://localhost:9001/token',
};

/**
 * Client information
 */
const clients = [

  {
    client_id: 'oauth-client',
    client_secret: 'oauth-client-secret',
    redirect_uris: ['http://localhost:9000/callback'],
    scope: 'read write delete',
  },
];

/**
 * Protected resource information
 */
const protectedResources = [
  {
    resource_id: 'protected-resource',
    resource_secret: 'protected-resource-secret',
  },
];

/**
 * Get client by ID
 * @param clientId
 */
const getClient = (clientId) => __.find(clients, (client) => client.client_id === clientId);

/**
 * Get resource by ID
 * @param resourceId
 */
const getProtectedResource = (resourceId) => __.find(protectedResources,
  (resource) => resource.resource_id === resourceId);

app.get('/', (req, res) => {
  res.render('index', { clients, authServer });
});

app.post('/token', (req, res) => {
  const auth = req.headers.authorization;
  if (auth) {
    // check the auth header
    const clientCredentials = decodeClientCredentials(auth);
    var clientId = clientCredentials.id;
    var clientSecret = clientCredentials.secret;
  }

  // otherwise, check the post body
  if (req.body.client_id) {
    if (clientId) {
      // if we've already seen the client's credentials in the authorization header, this is an error
      console.log('Client attempted to authenticate with multiple methods');
      res.status(401).json({ error: 'invalid_client' });
      return;
    }

    var clientId = req.body.client_id;
    var clientSecret = req.body.client_secret;
  }

  const client = getClient(clientId);
  if (!client) {
    console.log('Unknown client %s', clientId);
    res.status(401).json({ error: 'invalid_client' });
    return;
  }

  if (client.client_secret != clientSecret) {
    console.log('Mismatched client secret, expected %s got %s', client.client_secret, clientSecret);
    res.status(401).json({ error: 'invalid_client' });
    return;
  }

  if (req.body.grant_type == 'password') {
    const { username } = req.body;

    usersDb.find({ username }, (err, user) => {
      if (user.length === 0) {
        res.status(401).json({ error: 'invalid_grant' });
        return;
      }
      const { password } = req.body;

      if (user[0].password != password) {
        console.log('Mismatched resource owner password, expected %s got %s', user[0].password, password);
        res.status(401).json({ error: 'invalid_grant' });
        return;
      }

      const rscope = req.body.scope ? user[0].scope.split(' ') : undefined;
      const cscope = client.scope ? client.scope.split(' ') : undefined;
      if (__.difference(rscope, cscope).length > 0) {
        res.status(401).json({ error: 'invalid_scope' });
        return;
      }
      const access_token = randomstring.generate();
      const refresh_token = randomstring.generate();

      tokenDb.insert([{ access_token, client_id: clientId, scope: rscope }]);
      tokenDb.insert([{ refresh_token, client_id: clientId, scope: rscope }]);

      const token_response = {
        access_token, token_type: 'Bearer', refresh_token, scope: rscope.join(' '),
      };

      res.status(200).json(token_response);
    });
  } else if (req.body.grant_type == 'refresh_token') {
    tokenDb.find({ refresh_token: req.body.refresh_token }, (err, token) => {
      if (token) {
        console.log('We found a matching refresh token: %s', req.body.refresh_token);
        if (token[0].client_id != clientId) {
          tokenDb.remove({ access_token: req.body.refresh_token });
          res.status(400).json({ error: 'invalid_grant' });
          return;
        }

        const access_token = randomstring.generate();
        tokenDb.insert([{ access_token, client_id: clientId, scope: token[0].scope }]);
        const token_response = {
          access_token, token_type: 'Bearer', refresh_token: token[0].refresh_token, scope: token[0].scope.join(' '),
        };
        res.status(200).json(token_response);
      } else {
        console.log('No matching token was found.');
        res.status(400).json({ error: 'invalid_grant' });
      }
    });
  } else {
    console.log('Unknown grant type %s', req.body.grant_type);
    res.status(400).json({ error: 'unsupported_grant_type' });
  }
});

app.post('/revoke', (req, res) => {
  const auth = req.headers.authorization;
  if (auth) {
    // check the auth header
    const clientCredentials = decodeClientCredentials(auth);
    var clientId = clientCredentials.id;
    var clientSecret = clientCredentials.secret;
  }

  // otherwise, check the post body
  if (req.body.client_id) {
    if (clientId) {
      // if we've already seen the client's credentials in the authorization header, this is an error
      console.log('Client attempted to authenticate with multiple methods');
      res.status(401).json({ error: 'invalid_client' });
      return;
    }

    var clientId = req.body.client_id;
    var clientSecret = req.body.client_secret;
  }

  const client = getClient(clientId);
  if (!client) {
    console.log('Unknown client %s', clientId);
    res.status(401).json({ error: 'invalid_client' });
    return;
  }

  if (client.client_secret != clientSecret) {
    console.log('Mismatched client secret, expected %s got %s', client.client_secret, clientSecret);
    res.status(401).json({ error: 'invalid_client' });
    return;
  }

  tokenDb.remove({ $and: [{ client_id: clientId }] }, { multi: true }, (err, numRemoved) => {
    console.log('Removed %s tokens', numRemoved);
    res.status(204).end();
  });
});

app.post('/introspect', (req, res) => {
  const auth = req.headers.authorization;
  const resourceCredentials = new Buffer.from(auth.slice('basic '.length), 'base64').toString().split(':');
  const resourceId = querystring.unescape(resourceCredentials[0]);
  const resourceSecret = querystring.unescape(resourceCredentials[1]);

  const resource = getProtectedResource(resourceId);
  if (!resource) {
    console.log('Unknown resource %s', resourceId);
    res.status(401).end();
    return;
  }

  if (resource.resource_secret != resourceSecret) {
    console.log('Mismatched secret, expected %s got %s', resource.resource_secret, resourceSecret);
    res.status(401).end();
    return;
  }

  const { intToken } = req.body;
  console.log('Introspecting token %s', intToken);
  tokenDb.find({ access_token: req.body.token }, (err, token) => {
    if (token.length > 0) {
      console.log('We found a matching token: %s', req.body.token);
      var introspectionResponse = {};
      introspectionResponse.active = true;
      introspectionResponse.iss = 'http://localhost:9001/';
      introspectionResponse.scope = token[0].scope.join(' ');
      introspectionResponse.client_id = token[0].client_id;

      res.status(200).json(introspectionResponse);
    } else {
      console.log('No matching token was found.');

      var introspectionResponse = {};
      introspectionResponse.active = false;
      res.status(401).json(introspectionResponse);
    }
  });
});

var decodeClientCredentials = function (auth) {
  const clientCredentials = new Buffer.from(auth.slice('basic '.length), 'base64').toString().split(':');
  const clientId = querystring.unescape(clientCredentials[0]);
  const clientSecret = querystring.unescape(clientCredentials[1]);
  return { id: clientId, secret: clientSecret };
};

const getScopesFromForm = function (body) {
  return __.filter(__.keys(body), (s) => __.string.startsWith(s, 'scope_'))
    .map((s) => s.slice('scope_'.length));
};

app.use('/', express.static('files/authorizationServer'));

tokenDb.remove({}, { multi: true });

var server = app.listen(9001, 'localhost', () => {
  const host = server.address().address;
  const { port } = server.address();

  console.log('OAuth Authorization Server is listening at http://%s:%s', host, port);
});
