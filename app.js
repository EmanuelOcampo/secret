//requiring all npm packages
require("dotenv").config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const FacebookStrategy = require("passport-facebook").Strategy;

const findOrCreate = require("mongoose-findOrCreate");


//declaring express as app
const app = express();

//static folder name public and intializing body parser
app.use(express.static("public"));
app.set("view engine", "ejs");
app.use(bodyParser.urlencoded({
  extended:true
}));


//setting  the express -session
app.use(session({
  secret: "Our little secret.",
  resave: false,
  saveUninitialized: false
}));

//initializing the sessions
app.use(passport.initialize());
app.use(passport.session());

//connect to userDB

// mongoose.connect("mongodb://localhost:27017/userDB");
mongoose.connect("mongodb+srv://admin-eman:emanuel101016@cluster0.yx9ipyx.mongodb.net/userDB");

//screating schema  for users
const userSchema = mongoose.Schema({
  email: String,
  password: String,
  googleId: String,
  facebookId: String,
  secret: String,
  name: String
});

//plugin the passport-local-mongoose package and findOrCreate
userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

//creating model that store to userSchema
const User = new mongoose.model("User", userSchema);


passport.use(User.createStrategy());

passport.serializeUser(function(user, done) {
    done(null, user.id);
  });

passport.deserializeUser(function(id, done) {
  User.findById(id, function(err, user) {
      done(err, user);
  });
});

//connecting  with google to authenticate  the user
passport.use(new GoogleStrategy({
    //clientID and clientSecret find in inv file
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
  },
  function(accessToken, refreshToken, profile, cb) {
    //find the email and if  not find then create instead to userDB
    User.findOrCreate({ username: profile.emails[0].value, googleId: profile.id, name: profile.displayName}, function (err, user) {
      console.log(profile);
      return cb(err, user);
    });
  }
));

passport.use(new FacebookStrategy({
    clientID: process.env.APP_ID,
    clientSecret: process.env.APP_SECRET,
    callbackURL: "http://localhost:3000/auth/facebook/secrets"
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ name: profile.displayName, facebookId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

app.get("/", function(req, res){
  res.render("home");
});

//to authenticate from google
app.get("/auth/google",
passport.authenticate("google", { scope: ["profile","email"] }));

//
app.get("/auth/google/secrets",
  //if the authenticate or register failed then back to login
  passport.authenticate("google", { failureRedirect: "/login" }),
  function(req, res) {
    // Successful authentication, redirect secrets
    res.redirect("/secrets");
  });

//to authenticate from facebook
app.get("/auth/facebook",
passport.authenticate("facebook",{scope:"email"}));

app.get("/auth/facebook/secrets",
passport.authenticate("facebook", { failureRedirect: "/login" }),
    function(req, res) {
      // Successful authentication, redirect secrets
      res.redirect("/secrets");
    }
  );

app.get("/login", function(req, res){
  res.render("login");
});

app.get("/register", function(req, res){
  res.render("register");
});

//posting secret
app.get("/secrets", function(req, res){
  //post all secret from all users
  User.find({"secret":{$ne:null}}, function(err, foundUsers){
    if (err){
      console.log(err);
    }else{
      if(foundUsers){
        const userID = req.user.id;
        User.findById(userID, function(err, profile){
          if (err) {
            console.log(err);
          } else {
            res.render("secrets", {usersWithSecrets:foundUsers, name:profile.name});
            // Successful authentication, redirect secrets
          }
        });

      }
    }
  });
});

app.get("/submit", function(req, res){
  if (req.isAuthenticated()){
    res.render("submit");
  } else {
    res.redirect("/login");
  }
});

app.post("/submit", function(req, res){
  const submittedSecret = req.body.secret;


  User.findById(req.user.id,function(err, foundUser){
    if(err){
      console.log(err);
    } else {
      if (foundUser){
        foundUser.secret = submittedSecret;
        foundUser.save(function(){
          res.redirect("/secrets");
        });
      }
    }
  })
});

//logout the user
app.get("/logout", function(req, res){
  req.logout(function(err){
    if (err) {
      console.log(err);
    }
  });
  res.redirect("/");
});

//register the user
app.post("/register", function(req, res){
  User.register({username: req.body.username}, req.body.password, function(err, user){
    if (err){
      console.log(err);
      res.redirect("/register");
    } else {
      passport.authenticate("local")(req, res, function(){
        res.render("/secrets");
      });
    }
  });
});


//login codes
app.post("/login",function(req, res){
  //getting the users username and password
  const user = new User ({
    username:req.body.username,
    password:req.body.password
  });

  req.login(user,function(err){
    if (err){
      console.log(err);
    } else {
      //authenticate the enter user if find in db
      passport.authenticate("local")(req, res, function(){
        res.redirect("/secrets");
      });
    }
  });
});

app.listen(3000,function(){
  console.log("server started on port 3000.");
});
