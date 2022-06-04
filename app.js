//jshint esversion:6

require('dotenv').config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require( 'passport-google-oauth2' ).Strategy;
const findOrCreate = require( "mongoose-findorcreate");

const app = express();


app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({extended:true}));
app.use(express.static("public"));


app.use(session({
    secret:process.env.SECRET,
    resave: false,
    saveUninitialized: false

}));

app.use(passport.initialize());
app.use(passport.session());

mongoose.connect("mongodb://localhost:27017/userDB");

const userSchema = new mongoose.Schema({
    email:String,
    password:String,
    googleId:String,
    secret:Array
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);


const User = new mongoose.model("User", userSchema);

passport.use(User.createStrategy());

passport.serializeUser(function(user,done){
    done(null,user.id);
});
passport.deserializeUser(function(id,done){
    User.findById(id,function(err,user){
        done(err,user);
    });
});

passport.use(new GoogleStrategy({
    clientID:  process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    passReqToCallback   : true
  },
  function(request, accessToken, refreshToken, profile, done) {
      console.log(profile);
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return done(err, user);
    });
  }
));


app.get("/", function(req, res) {
    res.render('home');
});

app.get('/auth/google',
  passport.authenticate('google', { scope:
      [ 'email', 'profile' ] }
));
app.get( '/auth/google/secrets',
    passport.authenticate( 'google', {
        successRedirect: '/secrets',
        failureRedirect: '/login'
}));

app.get("/login", function(req, res) {
    res.render('login');
});
app.get("/register", function(req, res) {
    res.render('register');
});

app.get("/secrets",function(req,res){
    User.find({secret:{$ne:null}},function (err, users){
      if(!err){
        if (users){
          res.render("secrets",{usersWithSecrets:users});
        }else {
          console.log(err);
        }
      }else {
        console.log(err);
      }
    });
  });

app.get("/submit",function(req, res) {
    if(req.isAuthenticated()){
        res.render('submit');
    }else{
        res.redirect("/login");
    }
});

app.post("/submit",(function (req, res){
    if(req.isAuthenticated()){
      User.findById(req.user.id,function (err, user){
        user.secret.push(req.body.secret);
        user.save(function (){
          res.redirect("/secrets");
        });
      });
   
    }else {
     res.redirect("/login");
    }
  }));

app.get("/logout", function(req, res) {
    req.logout();
    res.redirect("/");
})

app.post("/register", function(req, res) {
    User.register({username:req.body.username},req.body.password,function(err,user){
        if(err){
            console.log(err);
            res.redirect('/register');
        }else{
            passport.authenticate("local")(req,res,function(){
                res.redirect('/secrets');
            });
        }
    });
   
   
});

app.post("/login", function(req, res){
    const user = new User({
        username : req.body.username,
        password : req.body.password
    });
    req.login(user,function(err){
        if(err){
            console.log(err)
        }else{
            passport.authenticate("local")(req,res,function(){
                res.redirect('/secrets');
            });
        }
    })
});





let PORT = 3000;

app.listen(PORT,function(){
    console.log("Server started on port 30000");
});