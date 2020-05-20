var express = require("express");
var bodyParser = require('body-parser');
var cons = require('consolidate');
var qs = require("qs");
var querystring = require('querystring');
var request = require("sync-request");
var __ = require('underscore');
var cors = require('cors');

var app = express();

app.use(bodyParser.urlencoded({ extended: true })); // support form-encoded bodies (for bearer tokens)

app.engine('html', cons.underscore);
app.set('view engine', 'html');
app.set('views', 'files/protectedResource');
app.set('json spaces', 4);

app.use('/', express.static('files/protectedResource'));
app.use(cors());

var protectedResources = {
		"resource_id": "protected-resource",
		"resource_secret": "protected-resource-secret"
};

var authServer = {
	introspectionEndpoint: 'http://localhost:9001/introspect'
};


var getAccessToken = function(req, res, next) {
	// check the auth header first
	var auth = req.headers['authorization'];
	var inToken = null;
	if (auth && auth.toLowerCase().indexOf('bearer') == 0) {
		inToken = auth.slice('bearer '.length);
	} else if (req.body && req.body.access_token) {
		// not in the header, check in the form body
		inToken = req.body.access_token;
	} else if (req.query && req.query.access_token) {
		inToken = req.query.access_token
	}
	
	console.log('Incoming token: %s', inToken);

	var form_data = qs.stringify({
		token: inToken
	});
	var headers = {
		'Content-Type': 'application/x-www-form-urlencoded',
		'Authorization': 'Basic ' + new Buffer.from(querystring.escape(protectedResources.resource_id) + ':' + querystring.escape(protectedResources.resource_secret)).toString('base64')
	};

	var tokRes = request('POST', authServer.introspectionEndpoint, 
		{	
			body: form_data,
			headers: headers
		}
	);
	
	if (tokRes.statusCode >= 200 && tokRes.statusCode < 300) {
		var body = JSON.parse(tokRes.getBody());
	
		console.log('Got introspection response', body);
		var active = body.active;
		if (active) {
			req.access_token = body;
		}
	}
	next();
	return;
};

var requireAccessToken = function(req, res, next) {
	if (req.access_token) {
		next();
	} else {
		res.status(401).end();
	}
};

var savedWords = [];

app.get('/words', getAccessToken, requireAccessToken, function(req, res) {
	if (__.contains(req.access_token.scope.split(' '), 'read')) {
		let position = savedWords.indexOf(req.query.word);
		if (position >= 0) {
			res.json({word: req.query.word, position: position, result: "get"});
		} else {
			res.json({word: req.query.word, position: -1, result: "noget"});
		}
	} else {
		res.set('WWW-Authenticate', 'Bearer realm=localhost:9002, error="insufficient_scope", scope="read"');  // see rfc6750
		res.status(403).json({error: 'insufficient_scope'});
	}
});

app.post('/words', getAccessToken, requireAccessToken, function(req, res) {
	if (__.contains(req.access_token.scope.split(' '), 'write')) {
		if (req.body.word) {
			savedWords.push(req.body.word);
			let position = savedWords.indexOf(req.body.word);
			res.json({word: req.body.word, position: position, result: "add"});
			res.status(201).end();
		} else {
			res.json({word: req.body.word, position: -1, result: "noadd"});
		}
	} else {
		res.set('WWW-Authenticate', 'Bearer realm=localhost:9002, error="insufficient_scope", scope="write"');
		res.status(403).json({error: 'insufficient_scope'});
	}
});

app.delete('/words', getAccessToken, requireAccessToken, function(req, res) {
	if (__.contains(req.access_token.scope.split(' '), 'delete')) {

		let position = savedWords.indexOf(req.query.word);
		if (position >= 0) {
			res.json({word: req.query.word, position: position, result: "rm"});
			savedWords.pop();
			res.status(201).end();
		} else {
			res.json({word: req.query.word, position: -1, result: "norm"});
		}
	} else {
		res.set('WWW-Authenticate', 'Bearer realm=localhost:9002, error="insufficient_scope", scope="delete"');
		res.status(403).json({error: 'insufficient_scope'});
	}
});


var server = app.listen(9002, 'localhost', function () {
  var host = server.address().address;
  var port = server.address().port;

  console.log('OAuth Resource Server listening at http://%s:%s', host, port);
});
 
