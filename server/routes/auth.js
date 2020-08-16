const router = require('express').Router();
const passport = require('passport');

const controllers = require('../controllers/auth');


router.get('/login', passport.authenticate('local-login'), controllers.localLogin);

router.get('/register', passport.authenticate('local-register'), controllers.localRegister);

router.get('/facebook', passport.authenticate('fb-login'));

router.get('/facebook/redirect', passport.authenticate('fb-login', {session:false}), controllers.fbLogin)

router.get('/google', passport.authenticate('google-login'));

router.get('/google/redirect', (req, res, next)=>{
	passport.authenticate('google-login', {session:false}, (err, user, info)=>{
		console.log('ERROR IS');
		console.log(err)
		req.user = user;req.err=err;req.info=info;
		next();
	})
} , controllers.googleLogin);

router.get('/twitter', passport.authenticate('twitter-login'), controllers.twitterLogin);

router.get('/twitter/redirect', passport.authenticate('twitter-login', {session:false}), controllers.twitterLogin);

module.exports = router;