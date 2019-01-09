var express = require('express');
var router = express.Router();

var userRestClient = require('./../rest-client/user-client');

/////////////////////// FILE UPLOAD ////////////////////////
const pubMediaDest = 'public/images/profiles';
//REF: https://www.npmjs.com/package/multer
var multer = require("multer");
var storage = multer.diskStorage(
  {
    destination: function (req, file, cb) {
      cb(null, pubMediaDest)
    },
    filename: function (req, file, cb) {
      cb(null, req.params.user_id + '-' + Date.now() + ".png")
    }
  }
);
var upload = multer({ storage: storage });
////////////////////////////////////////////////////////////

router.get('/:user_id', function (req, res, next) {
  let userId = req.params.user_id;
  let token = req.session.key.token;

  userRestClient.getUserProfile(userId, token, function (responseCode, data) {
    if (responseCode == 200) {
      return res.status(responseCode).json({
        code: responseCode,
        title: "Successfully retrieving of user profile",
        data: data
      });
    }
    return res.status(responseCode).json({
      code: responseCode,
      title: "An error has occurred",
      error: data
    });
  });
});

/**
 * METODO PARA ACTUALIZAR LOS DATOS DE PERFIL
 */
router.post('/:user_id', upload.single('user_file'), function (req, res, next) {
  let token = req.session.key.token;
  let user_id = req.params.user_id;

  let dest, mediaProfile;

  if (req.file) {
    dest = req.file.path;
    dest = dest.replace("public/", "");
    mediaProfile = "/" + dest;
  }

  userRestClient.patchUser(user_id, req.body, mediaProfile, token, function (responseCode, data) {
    if (responseCode == 200) {
      return res.status(responseCode).json({
        code: responseCode,
        title: "User has been updated successfully",
        data: data
      });
    }
    return res.status(responseCode).json({
      code: responseCode,
      title: "An error has occurred",
      error: data
    });
  });
});

router.get('/', function (req, res, next) {
  if (!req.query.pub_id && !req.query.com_id) {
    return res.status(400).json({
      code: responseCode,
      title: "An error has ocurred",
      error: "A pub id or comment id must be provided"
    });
  }
  let relevanceType = (req.query.pub_id) ? req.query.pub_id : req.query.com_id;
  let comRelevance = (req.query.com_relevance) ? req.query.com_relevance : false;
  let limit = (req.query.limit) ? req.query.limit : null;
  let offset = (req.query.offset) ? req.query.offset : null;
  let token = req.session.key.token;

  userRestClient.getUserSupporters(relevanceType, comRelevance, limit, offset, token, function (responseCode, data) {
    if (responseCode == 200) {
      return res.status(responseCode).json({
        code: responseCode,
        title: "Successfully retrieving of supporter users",
        supporters: data
      });
    }
    return res.status(responseCode).json({
      code: responseCode,
      title: "An error has occurred",
      error: data
    });
  });
});

module.exports = router;
