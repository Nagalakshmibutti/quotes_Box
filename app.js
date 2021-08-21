//jshint esversion:6
require("dotenv").config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");

//cookies session  and applyting encryption for password of users using passport-locla-mongoose method
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");


//google authentication 

const GoogleStrategy = require("passport-google-oauth20").Strategy;
const findOrCreate = require("mongoose-findorcreate");

const app = express();

app.set("view engine", "ejs");
app.use(bodyParser.urlencoded({
    extended : true
}));


//Encryption of passwords

app.use(session({
    secret : "Our Little Secret.",
    resave : false,
    saveUninitialized :false
}));
app.use(passport.initialize());
app.use(passport.session());

//Creating mongodb data base for users and data base name us userDB
mongoose.connect("mongodb://localhost:27017/userDB", {useNewUrlParser:true, useUnifiedTopology:true})
mongoose.set('useCreateIndex', true);

//defining Attributes in user schema 
const userSchema = new mongoose.Schema( {
    email : String,
    password : String,
    googleId : String,
    secret : String
});

//adding passport encryption for useSchema
userSchema.plugin(passportLocalMongoose);

//Adding mongodb dindOrCreate package to schema
userSchema.plugin(findOrCreate);

//mongoose model
const User = mongoose.model("User", userSchema);

//google authentication 
passport.use(User.createStrategy());
/* passport.serializeUser(User.serializeUser());
passport.deserializeUser(User.deserializeUser()); */

//serializeUser for authentication 
passport.serializeUser(function(user, done){
    done(null, user.id);
});

//deserializeUser for authentication
passport.deserializeUser(function(id, done){
    User.findById(id, function(err, user){
        done(err, user);
    });
});


//Google strategy
passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secret",
    userProfileURL : "https://www.googleapis.com/oauth2/v3/userinfo",
   // passReqToCallback:true,
    
  },
  function(accessToken, refreshToken, profile, cb) {
      //This console statement will give the info of user who has login with google account
      console.log(profile);
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

app.get("/", function(req, res){
    res.render("home");
});

//Used when user login with the google account
app.get("/auth/google",
    passport.authenticate('google',{ scope: ["profile"]})
);

app.get("/auth/google/secret",
    passport.authenticate('google', {failureRedirect: "/login"}),
    function(req, res){
        //Successful authentication, redirect to secrets
        res.redirect("/secrets");
    }
)

app.get("/login", function(req, res){
    res.render("login");
});

app.get("/register", function(req, res){
    res.render("register");
});

//Secrets page with out login
app.get("/secrets", function(req, res){
   User.find({"secret":{$ne: null}}, function(err, foundUsers){
       if(err){
           console.log(err);
       }else{
           if(foundUsers){
               res.render("secrets", {userWithSecrets : foundUsers});
           }
       }
   });
});

//secret submition 
app.get("/submit", function(req, res){
    if(req.isAuthenticated()){
        res.render("submit");
    }else{
        res.redirect("/login");
    }
});

//secrets post page
app.post("/submit", function(req, res){
    const submittedSecret = req.body.secret;
    User.findById(req.user.id, function(err, foundUser){
        if(err){
            console.log(err);
        }else{
            if(foundUser){
                foundUser.secret = submittedSecret;
                foundUser.save(function(){
                    res.redirect("/secrets")
                });
            }
        }
    });
});

app.get("/logout", function(req, res){
    req.logout();
    res.redirect("/")
});

app.post("/register", function(req, res){
   User.register({username : req.body.username}, req.body.password, function(err, user){
       if(err){
           console.log(err);
           res.redirect("/register");
       }else{
           passport.authenticate("local")(req, res, function(){
               res.redirect("/secrets");
           });
       }
   });
});

app.post("/login", function(req, res){
    const user = new User({
        username : req.body.username,
        password : req.body.password
    });

    req.login(user , function(err){
        if(err){
            console.log(err)
        }else{
            passport.authenticate("local")(req, res, function(){
                res.redirect("/secrets");
            });
        }
    });
  
});

app.listen(3000, function(){
    console.log("server has started on local host 3000");
})