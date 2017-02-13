var express = require('express');
var bodyParser = require('body-parser');
var morgan = require('morgan');
var mongoose = require('mongoose');
var jwt    = require('jsonwebtoken'); // used to create, sign, and verify tokens

var app = express();

// our config file
var config = require('./config'); 

// our mongoose model
var User   = require('./models/user');

// connect to the database
mongoose.connect(config.database); 

// set the secret
app.set('tokenSecret', config.secret);

// register the bodyParser middleware for processing json
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({extended: false}));

// use morgan to log requests to the console
app.use(morgan('dev'));

// main route for testing
app.get('/',function(req,res){

	res.end('it works!')
});

var userRouter = express.Router();

userRouter.post('/', function(req, res) {

	// create a new user
	var newUser = new User({ 
		email: req.body.email, 
		password: req.body.password
	});

	// save the new user
	newUser.save(function(err) {
		if (err) {
			throw err;
		}

		var token = jwt.sign(newUser, app.get('tokenSecret'), {
			expiresIn: "1d" // expires in 1 day
		});

		res.json({ 
			success: true,
			token: token
		});
	});
});

userRouter.post('/login', function(req, res) {

	// find the user
	User.findOne({
		email: req.body.email
	}, function(err, user) {

		if (err) { 
			throw err;
		}

		if (!user) {
			res.json({success: false, message: 'User not found.'});
		} 
		else if (user) {

			// check if password matches
			if (user.password != req.body.password) {

				res.json({ success: false, message: 'Wrong password.' });
			} 
			else {

				// if user is found and password is right
				// create a token
				var token = jwt.sign(user, app.get('tokenSecret'), {
					expiresIn: "1d" // expires in 1 day
				});

				// return the information including token as JSON
				res.json({
					success: true,
					message: 'Login Successful',
					token: token
				});
			}   

		}

	});
});

// route middleware to verify a token
// All routes added to userRouter after this will contain this middleware. All
// routes added above do not use it.
userRouter.use(function(req, res, next) {

	// check header or url parameters or post parameters for token
	var token = req.body.token || req.query.token || req.headers['x-access-token'];

	// decode the token
	if (token) {

		// verifies secret and checks exp
		jwt.verify(token, app.get('tokenSecret'), function(err, decoded) {      
			
			if (err) {
				return res.json({ success: false, message: 'Failed to authenticate token.' });    
			} 
			else {
				// if everything is good, save to request for use in other routes
				req.decoded = decoded;    
				next();
			}
		});

	} 
	else {

		// if there is no token
		// return an error
		return res.status(403).send({ 
			success: false, 
			message: 'No token provided.' 
		});

	}
});

// get the list of users
// this requires a user token
userRouter.get('/', function(req, res) {
	User.find({}, function(err, users) {
		res.json(users);
	});
}); 

app.use('/user', userRouter);

app.listen(8000,function(){
	console.log("App Started on port 8000");
});