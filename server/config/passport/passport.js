const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const credentials = require('../../secret/credentials');
const FacebookStrategy = require('passport-facebook').Strategy;
const GoogleStrategy = require('passport-google-oauth').OAuth2Strategy;
const TwitterStrategy = require('passport-twitter').Strategy;
const User = require('../../modals/user');


// passport setup for local login
passport.use('local-login', new LocalStrategy({
	usernameField:'username',
	passwordField:'password'
}, (username, password, done)=>{
	let userdata;
	User.findUser(username).then(user=>{
		if(!user)
			return done(null, false, {message:"User doesn't exist", status:404});
		userdata = user;
		return bcrypt.compare(password, user.password);
	}).then(passwordMatch=>{
		if(!passwordMatch)
			return done(null, false, {message:"Invalid credentials", status:442});
		return done(null, userdata);
	}).catch(err=>done(err));
}));

// passport setup for local register
passport.use('local-register', new LocalStrategy({
	usernameField:'username',
	passwordField:'password',
	passReqToCallback:true
}, (req, username, password, done)=>{
	User.findUser(username).then(user=>{
		if(user)
			return done(null, false, {message:"User exists, Please Login !", status:442});
		return bcrypt.hash(password, 12);
	}).then(passcode=>{
		if(!password)
			return done(null, false, {message:"Internal Server Error", status:500});
		const newUser = new User({
			username:username,
			email:req.body.email,
			password:passcode
		});
		return newUser.save();
	}).then(result=>{
		if(!result)
			return done(null, false, {message:"Registration Failed, Try again !", status: 500});
		return done(null, true, {message:"User Added", status:201});
	}).catch(err=>done(err));
}));

// passport facebook auth
passport.use('fb-login', new FacebookStrategy({
	...credentials.FB,
	callbackURL:'/auth/facebook/redirect'
}, (accessToken, refreshToken, profile, done) => {
	User.findUserFb(profile.id).then(user=>{
		if(!user){
			let newUser = new User({
				facebook:{
					fbId:profile.id,
					token:accessToken
				},
				name:profile.displayName
			});
			return newUser.save();
		}
		return Promise.resolve(true);
	}).then(result=>{
		if(!result)
			return done(null, false, {message:"Facebook Login failed", status:500});
		
		return done(null, {id:profile.id});
	}).catch(err=>done(err));
}));

// passport google auth
passport.use('google-login', new GoogleStrategy({
	...credentials.GOOGLE,
	callbackURL:'/auth/google/redirect'
}, (accessToken, refreshToken, profile, done)=>{
	User.findUser(profile.emails[0].value).then(user=>{
		if(!user){
			let newUser = new User({
				email: profile.emails[0].value,
				google:{
					googleId:profile.id,
					token:accessToken
				},
				name:profile.displayName
			});
			return newUser.save();
		}
		return Promise.resolve(true);
	}).then(result=>{
		if(!result)
			return done(null, false, {message:"Google Login failed", status:500});
		return done(null, {id:profile.id});
	}).catch(err=>done(err));
}));

// passport twitter auth
passport.use('twitter-login', new TwitterStrategy({
	...credentials.TWITTER,
	callbackURL:'/auth/twitter/redirect'
}, (token, tokenSecret, profile, done)=>{
	User.findUserTwitter(profile.id).then(user=>{
		if(!user){
			let newUser = new User({
				twitter:{
					twitterId:profile.id,
					token:token
				},
				name:profile.displayName
			});
			return newUser.save();
		}
		return Promise.resolve(true);
	}).then(result=>{
		if(!result)
			return done(null, false, {message:"Twitter Login failed", status:500});
		return done(null, {id:profile.id});
	}).catch(err=>done(err));
}));