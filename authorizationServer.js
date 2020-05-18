var express = require('express');
var url = require("url");
var bodyParser = require('body-parser');
var randomstring = require("randomstring");
var cons = require('consolidate');
var Datastore = require('nedb'), token_db = new Datastore({filename: './tokens.nedb', autoload: true});
var Datastore = require('nedb'), users_db = new Datastore({filename: './users.nedb', autoload: true});
var querystring = require('querystring');
var __ = require('underscore');
__.string = require('underscore.string');

var app = express();

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true })); // support form-encoded bodies (for the token endpoint)

app.engine('html', cons.underscore);
app.set('view engine', 'html');
app.set('views', 'files/authorizationServer');
app.set('json spaces', 4);

/**
 * Init Users database
 */
users_db.count({}, function (err, count) {
	if (!count) {
		users_db.insert(
		[
				{username: 'alice', password: 'password', scope: 'read write delete'},
				{username: 'bob', password: 'my_secret_password', scope: 'read'}
			], function (err, docs) {
		});
	}
});

/**
 * Authorization server information
 */
var authServer = {
	authorizationEndpoint: 'http://localhost:9001/authorize',
	tokenEndpoint: 'http://localhost:9001/token'
};

// client information
var clients = [

	{
		"client_id": "oauth-client-1",
		"client_secret": "oauth-client-secret-1",
		"redirect_uris": ["http://localhost:9000/callback"],
		"scope": "read write delete"
	}
];

var protectedResources = [
	{
		"resource_id": "protected-resource-1",
		"resource_secret": "protected-resource-secret-1"
	}
];


var getClient = function(clientId) {
	return __.find(clients, function(client) { return client.client_id == clientId; });
};

var getProtectedResource = function(resourceId) {
	return __.find(protectedResources, function(resource) { return resource.resource_id == resourceId; });
};

app.get('/', function(req, res) {
	res.render('index', {clients: clients, authServer: authServer});
});

app.post("/token", function(req, res){

	var auth = req.headers['authorization'];
	if (auth) {
		// check the auth header
		var clientCredentials = decodeClientCredentials(auth);
		var clientId = clientCredentials.id;
		var clientSecret = clientCredentials.secret;
	}
	
	// otherwise, check the post body
	if (req.body.client_id) {
		if (clientId) {
			// if we've already seen the client's credentials in the authorization header, this is an error
			console.log('Client attempted to authenticate with multiple methods');
			res.status(401).json({error: 'invalid_client'});
			return;
		}
		
		var clientId = req.body.client_id;
		var clientSecret = req.body.client_secret;
	}
	
	var client = getClient(clientId);
	if (!client) {
		console.log('Unknown client %s', clientId);
		res.status(401).json({error: 'invalid_client'});
		return;
	}
	
	if (client.client_secret != clientSecret) {
		console.log('Mismatched client secret, expected %s got %s', client.client_secret, clientSecret);
		res.status(401).json({error: 'invalid_client'});
		return;
	}

	if (req.body.grant_type == 'password') {
		var username = req.body.username;

		users_db.find({username:username}, function (err, user) {
			if (user.length === 0) {
				res.status(401).json({error: 'invalid_grant'});
				return;
			}
			var password = req.body.password;

			if (user[0].password != password) {
				console.log('Mismatched resource owner password, expected %s got %s', user[0].password, password);
				res.status(401).json({error: 'invalid_grant'});
				return;
			}

			var rscope = req.body.scope ? user[0].scope.split(' ') : undefined;
			var cscope = client.scope ? client.scope.split(' ') : undefined;
			if (__.difference(rscope, cscope).length > 0) {
				res.status(401).json({error: 'invalid_scope'});
				return;
			}
			var access_token = randomstring.generate();
			var refresh_token = randomstring.generate();

			token_db.insert([{ access_token: access_token, client_id: clientId, scope: rscope}]);
			token_db.insert([{ refresh_token: refresh_token, client_id: clientId, scope: rscope }]);

			var token_response = { access_token: access_token, token_type: 'Bearer',  refresh_token: refresh_token, scope: rscope.join(' ') };

			res.status(200).json(token_response);
			});

	} else if (req.body.grant_type == 'refresh_token') {
		token_db.find({refresh_token: req.body.refresh_token}, function(err, token) {
			if (token) {
				console.log("We found a matching refresh token: %s", req.body.refresh_token);
				if (token[0].client_id != clientId) {
					token_db.remove({access_token: req.body.refresh_token});
					res.status(400).json({error: 'invalid_grant'});
					return;
				}

				var access_token = randomstring.generate();
				token_db.insert([{ access_token: access_token, client_id: clientId, scope: token[0].scope}]);
				var token_response = { access_token: access_token, token_type: 'Bearer',  refresh_token: token[0].refresh_token, scope: token[0].scope.join(' ') };
				res.status(200).json(token_response);
				return;
			} else {
				console.log('No matching token was found.');
				res.status(400).json({error: 'invalid_grant'});
				return;
			}
		});
	} else {
		console.log('Unknown grant type %s', req.body.grant_type);
		res.status(400).json({error: 'unsupported_grant_type'});
	}
});

app.post('/revoke', function(req, res) {
	var auth = req.headers['authorization'];
	if (auth) {
		// check the auth header
		var clientCredentials = decodeClientCredentials(auth);
		var clientId = clientCredentials.id;
		var clientSecret = clientCredentials.secret;
	}
	
	// otherwise, check the post body
	if (req.body.client_id) {
		if (clientId) {
			// if we've already seen the client's credentials in the authorization header, this is an error
			console.log('Client attempted to authenticate with multiple methods');
			res.status(401).json({error: 'invalid_client'});
			return;
		}
		
		var clientId = req.body.client_id;
		var clientSecret = req.body.client_secret;
	}
	
	var client = getClient(clientId);
	if (!client) {
		console.log('Unknown client %s', clientId);
		res.status(401).json({error: 'invalid_client'});
		return;
	}
	
	if (client.client_secret != clientSecret) {
		console.log('Mismatched client secret, expected %s got %s', client.client_secret, clientSecret);
		res.status(401).json({error: 'invalid_client'});
		return;
	}

	token_db.remove( {$and: [{client_id: clientId}] }, {multi:true}, function(err, numRemoved) {
		console.log("Removed %s tokens", numRemoved);
		res.status(204).end();
		return;
	});
	
});

app.post('/introspect', function(req, res) {
	var auth = req.headers['authorization'];
	var resourceCredentials = new Buffer.from(auth.slice('basic '.length), 'base64').toString().split(':');
	var resourceId = querystring.unescape(resourceCredentials[0]);
	var resourceSecret = querystring.unescape(resourceCredentials[1]);

	var resource = getProtectedResource(resourceId);
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

	var token = req.body.token;
	console.log('Introspecting token %s', token);
	token_db.find({access_token: req.body.token }, function(err, token) {
		if (token) {
			console.log("We found a matching token: %s", req.body.token);

			var introspectionResponse = {};
			introspectionResponse.active = true;
			introspectionResponse.iss = 'http://localhost:9001/';
			introspectionResponse.scope = token[0].scope.join(' ');
			introspectionResponse.client_id = token[0].client_id;

			res.status(200).json(introspectionResponse);
			return;
		} else {
			console.log('No matching token was found.');

			var introspectionResponse = {};
			introspectionResponse.active = false;
			res.status(200).json(introspectionResponse);
			return;
		}
	});


});

var decodeClientCredentials = function(auth) {
	var clientCredentials = new Buffer.from(auth.slice('basic '.length), 'base64').toString().split(':');
	var clientId = querystring.unescape(clientCredentials[0]);
	var clientSecret = querystring.unescape(clientCredentials[1]);	
	return { id: clientId, secret: clientSecret };
};

var getScopesFromForm = function(body) {
	return __.filter(__.keys(body), function(s) { return __.string.startsWith(s, 'scope_'); })
				.map(function(s) { return s.slice('scope_'.length); });
};

app.use('/', express.static('files/authorizationServer'));

token_db.remove({}, {multi: true});

var server = app.listen(9001, 'localhost', function () {
  var host = server.address().address;
  var port = server.address().port;

  console.log('OAuth Authorization Server is listening at http://%s:%s', host, port);
});
 
