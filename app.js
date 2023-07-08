var express = require("express"),
	mongoose = require("mongoose"),
	passport = require("passport"),
	bodyParser = require("body-parser"),
	LocalStrategy = require("passport-local"),
	passportLocalMongoose =
		require("passport-local-mongoose")
	bcrypt = require ('bcrypt');
const User = require("./model/User");
var app = express();

mongoose.connect("mongodb://localhost/27017");

app.set("view engine", "ejs");
app.use(bodyParser.urlencoded({ extended: true }));
app.use(require("express-session")({
	secret: "Node must stick",
	resave: false,
	saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());

passport.use(new LocalStrategy(User.authenticate()));
passport.serializeUser(User.serializeUser());
passport.deserializeUser(User.deserializeUser());

//=====================
// ROUTES
//=====================

// Showing home page
app.get("/", (req, res) => {
	res.render("home");
});

// Showing secret page
app.get("/secret", isLoggedIn, (req, res) => {
	res.render("secret");
});

// Showing register form
app.get("/register", (req, res) => {
	res.render("register");
});

// Handling user signup
app.post("/register", async (req, res) => {
	try {
	  const { username, password } = req.body;
  
	  // Generate a salt to use for hashing
	  const salt = await bcrypt.genSalt(10);
  
	  // Hash the password using bcrypt
	  const hashedPassword = await bcrypt.hash(password, salt);
  
	  const user = await User.create({
		username,
		password: hashedPassword
	  });
  
	  // Render a success message
	  res.render("registrationSuccess", { username: user.username });
	} catch (error) {
	  // Handle registration error
	  res.status(400).json({ error: "Error registering user" });
	}
  });

//Showing login form
app.get("/login", (req, res) => {
	res.render("login");
});

//Handling user login
app.post("/login", async (req, res) => {
	try {
		// check if the user exists
		const user = await User.findOne({ username: req.body.username });
		if (user) {
		//check if password matches
		const result = req.body.password === user.password;
		if (result) {
			res.render("secret", { username: user.username});
		} else {
			res.status(400).json({ error: "password doesn't match" });
		}
		} else {
		res.status(400).json({ error: "User doesn't exist" });
		}
	} catch (error) {
		res.status(400).json({ error });
	}
});



//Handling user logout
app.get("/logout", (req, res) => {
	req.logout( (err) => {
		if (err) { return next(err); }
		res.redirect('/');
	});
});



function isLoggedIn(req, res, next) {
	if (req.isAuthenticated()) return next();
	res.redirect("/login");
}

var port = process.env.PORT || 3000;
app.listen(port, function () {
	console.log("Server Has Started!");
});
