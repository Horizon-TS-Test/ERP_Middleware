var express = require('express');
var router = express.Router();
var publicationRestClient = require('./../rest-client/publication-client');
var postClaim = require('./../controllers/pub-controller');
var pubType = require('./../const/pub-type');

/////////////////////// FILE UPLOAD ////////////////////////
const pubMediaDest = 'public/images/pubs';
//REF: https://www.npmjs.com/package/multer
var multer = require("multer");
var storage = multer.diskStorage(
  {
    destination: function (req, file, cb) {
      cb(null, pubMediaDest)
    },
    filename: function (req, file, cb) {
      cb(null, req.body.userId + '-' + Date.now() + ".png")
    }
  }
);
var upload = multer({ storage: storage });
////////////////////////////////////////////////////////////

router.get('/filter/:city', function (req, res, next) {
  let cityFilter = req.params.city;
  let token = req.session.key.token;

  publicationRestClient.getPubFilter(token, cityFilter, function (responseCode, data) {
    if (responseCode == 200) {
      return res.status(responseCode).json({
        code: responseCode,
        title: "Successfully retrieving of publication data with filter",
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
  let token = req.session.key.token;
  let limit = isNaN(parseInt(req.query.limit)) ? null : req.query.limit;
  let offset = (req.query.offset) ? req.query.offset : null;
  let userId = (req.query.user_id) ? req.query.user_id : null;
  let typeId = null;
  if(req.query.pub) {
    typeId = pubType.publication;
  }
  else if(req.query.claim) {
    typeId = pubType.claim;
  }

  publicationRestClient.getPubByPage(token, limit, offset, userId, typeId, function (responseCode, data) {
    if (responseCode == 200) {
      return res.status(responseCode).json({
        code: responseCode,
        title: "Successfully retrieving of publication data with pagination",
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

router.post('/', upload.array('media_files[]', 5), (req, res, next) => {
  var token = req.session.key.token;

  postClaim.postPub(req.body, req.files, token, req.io, function (pubData) {
    if (pubData.isError) {
      return res.status(pubData.code).json({
        code: pubData.code,
        title: pubData.title,
        error: pubData.data
      });
    }

    return res.status(pubData.code).json({
      code: pubData.code,
      title: pubData.title,
      data: pubData.data
    });
  });
});

router.get('/:pubId', function (req, res, next) {
  let pubId = req.params.pubId;
  let token = req.session.key.token;

  publicationRestClient.getPub(pubId, token, function (responseCode, data) {
    if (responseCode == 200) {
      return res.status(responseCode).json({
        code: responseCode,
        title: "Successfully retrieving pub detail",
        pub: data
      });
    }
    return res.status(responseCode).json({
      code: responseCode,
      title: "An error has occurred",
      error: data
    });
  });
});

router.post('/transmission/:pubId', function (req, res, next) {
  let pubId = req.params.pubId;
  let token = req.session.key.token;

  publicationRestClient.patchPub(req.body, null, token, function (responseCode, data) {
    if (responseCode == 200) {
      return res.status(responseCode).json({
        code: responseCode,
        title: "Transmission has been created stopped successfully",
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
 * Funcion para obtener las quejas por parroquia
 */

router.get('/parish/:parish', function (req, res, next) {
  let parishFilter = req.params.parish;
  let token = req.session.key.token;

  publicationRestClient.getPubFilterCity(token, parishFilter, function (responseCode, data) {
    if (responseCode == 200) {
      return res.status(responseCode).json({
        code: responseCode,
        title: "Successfully retrieving of publication data with filter",
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

/*router.get('/delete/:todoId', function (req, res, next) {
  let todoId = req.params.todoId;
  let token = req.session.key.token;
 
  publicationRestClient.deleteTodo(todoId, token, function (responseCode, data) {
    if (responseCode == 200) {
      return res.status(responseCode).json({
        code: responseCode,
        title: "Todo has been deleted successfully",
        data: data
      });
    }
    return res.status(responseCode).json({
      code: responseCode,
      title: "An error has occurred",
      error: data
    });
  });
});*/
/**
 * Funciones de filtro
 */

router.get('/location/:parish', function (req, res, next) {
  let parishFilter = req.params.parish;
  let token = req.session.key.token;

  publicationRestClient.getPubFilterParish(token, parishFilter, function (responseCode, data) {
    if (responseCode == 200) {
      return res.status(responseCode).json({
        code: responseCode,
        title: "Successfully retrieving of publication data with filter",
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
 * Funcion para llamar a publicaciones por fecha 
 */
router.get('/date/:fecha', function (req, res, next) {
  let fechaFilter = req.params.fecha;
  var fechaJSON=JSON.parse(fechaFilter);
  let fechai = fechaJSON.fechai;
  let fechaf = fechaJSON.fechaf;
  let token = req.session.key.token;

  publicationRestClient.getPubFilterDate(token,fechai, fechaf, function (responseCode, data) {
    if (responseCode == 200) {
      return res.status(responseCode).json({
        code: responseCode,
        title: "Successfully retrieving of publication data with filter",
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
 * Funcion para llamar a publicaciones por fecha 
 */
router.get('/dateParish/:fechaParish', function (req, res, next) {
  let fechaFilter = req.params.fechaParish;
  var fechaJSON=JSON.parse(fechaFilter);
  let fechai = fechaJSON.fechai;
  let fechaf = fechaJSON.fechaf;
  let parishId = fechaJSON.parishId;
  let token = req.session.key.token;

  publicationRestClient.getPubFilterDateParish(token,fechai, fechaf, parishId, function (responseCode, data) {
    if (responseCode == 200) {
      return res.status(responseCode).json({
        code: responseCode,
        title: "Successfully retrieving of publication data with filter",
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

module.exports = router;
