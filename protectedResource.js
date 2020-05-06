/* BEGINNING OF SKELETON */

var express = require("express");
var cons = require('consolidate');
var bodyParser = require('body-parser');
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

var resource = {
	"name": "Protected Resource",
	"description": "This data has been protected by OAuth 2.0"
};

var server = app.listen(9002, 'localhost', function () {
	var host = server.address().address;
	var port = server.address().port;

	console.log('OAuth Resource Server is listening at http://%s:%s', host, port);
});

/* END OF SKELETON */

var qs = require("qs");
var querystring = require('querystring');
var request = require("sync-request");

var protectedResources = {
		"resource_id": "protected-resource-1",
		"resource_secret": "protected-resource-secret-1"
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
		'Authorization': 'Basic ' + new Buffer(querystring.escape(protectedResources.resource_id) + ':' + querystring.escape(protectedResources.resource_secret)).toString('base64')
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
	if (__.contains(req.access_token.scope, 'read')) {
		res.json({words: savedWords.join(' '), timestamp: Date.now()});
	} else {
		res.set('WWW-Authenticate', 'Bearer realm=localhost:9002, error="insufficient_scope", scope="read"');
		res.status(403);
	}
});

app.post('/words', getAccessToken, requireAccessToken, function(req, res) {
	if (__.contains(req.access_token.scope, 'write')) {
		if (req.body.word) {
			savedWords.push(req.body.word);
		}
		res.status(201).end();
	} else {
		res.set('WWW-Authenticate', 'Bearer realm=localhost:9002, error="insufficient_scope", scope="write"');
		res.status(403);
	}
});

app.delete('/words', getAccessToken, requireAccessToken, function(req, res) {
	if (__.contains(req.access_token.scope, 'delete')) {
		savedWords.pop();
		res.status(201).end();
	} else {
		res.set('WWW-Authenticate', 'Bearer realm=localhost:9002, error="insufficient_scope", scope="delete"');
		res.status(403);
	}
});

app.get('/produce', getAccessToken, requireAccessToken, function(req, res) {
	var produce = {fruit: [], veggies: [], meats: []};
	if (__.contains(req.access_token.scope, 'fruit')) {
		produce.fruit = ['apple', 'banana', 'kiwi'];
	}
	if (__.contains(req.access_token.scope, 'veggies')) {
		produce.veggies = ['lettuce', 'onion', 'potato'];
	}
	if (__.contains(req.access_token.scope, 'meats')) {
		produce.meats = ['bacon', 'steak', 'chicken breast'];
	}
	console.log('Sending produce: ', produce);
	res.json(produce);
});

var aliceFavorites = {
	'movies': ['The Multidmensional Vector', 'Space Fights', 'Jewelry Boss'],
	'foods': ['bacon', 'pizza', 'bacon pizza'],
	'music': ['techno', 'industrial', 'alternative']
};

var bobFavories = {
	'movies': ['An Unrequited Love', 'Several Shades of Turquoise', 'Think Of The Children'],
	'foods': ['bacon', 'kale', 'gravel'],
	'music': ['baroque', 'ukulele', 'baroque ukulele']
};

app.get('/favorites', getAccessToken, requireAccessToken, function(req, res) {
	if (req.access_token.user == 'alice') {
		res.json({user: 'Alice', favorites: aliceFavorites});
	} else if (req.access_token.user == 'bob') {
		res.json({user: 'Bob', favorites: bobFavorites});
	} else {
		var unknown = {user: 'Unknown', favorites: {movies: [], foods: [], music: []}};
		res.json(unknown);
	}
});

app.options('/resource', cors());

app.post("/resource", cors(), getAccessToken, function(req, res){

	if (req.access_token) {
		res.json(resource);
	} else {
		res.status(401).end();
	}
	
});
