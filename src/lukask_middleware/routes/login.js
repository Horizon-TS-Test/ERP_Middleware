var express = require('express');
var router = express.Router();
var cryptoGen = require('./../tools/crypto-generator');
var loginClient = require('./../rest-client/login-client');

/* REST API CLIENT - LOGIN METHOD */
router.post('/', function (req, res, next) {
  let user = cryptoGen.decryptPass(req.body.username);
  let password = cryptoGen.decryptPass(req.body.password);

  loginClient.responseLogin(user, password, function (responseCode, data) {
    if (responseCode == 200) {
      //GENERATING CRYPTO ID FOR USER SESSION:
      let encryptedUserKey = cryptoGen.encrypt(user + "-" + Date.now());
      let encryptedUserId = cryptoGen.encryptPass(data.user_id + "");
      ///////////////////////////////////////

      //CALLING TO OUR SESSION STORE INSTANCE:
      req.session.key = {
        crypto_user_id: encryptedUserKey,
        token: data.token
      };
      ////////////////////////////////////////
      
      return res.status(responseCode).json({
        code: responseCode,
        title: "Successfully calling of login REST API method",
        data: {
          user_key: encryptedUserKey,
          user_id: encryptedUserId
        }
      });
    }
    return res.status(responseCode).json({
      code: responseCode,
      title: "An error has occurred",
      error: data
    });
  });
});

router.post('/logout', function (req, res, next) {
  if(req.session) {
    req.session.destroy();
  }
  return res.status(200).json({
    code: 200,
    title: "You've logout from the app",
    data: true
  });
});

module.exports = router;