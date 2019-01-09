var express = require('express');
var router = express.Router();

var parroquiaRestClient = require('./../rest-client/parroquia-client');

router.get('/', function (req, res, next) {
    let canton_id = req.query.canton_id;

    parroquiaRestClient.getParroquia(canton_id, function (responseCode, data) {
        if (responseCode == 200) {
            return res.status(responseCode).json({
                code: responseCode,
                title: "Successfully retrieving of parroquia data",
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

router.get('/:canton_id', function (req, res, next) {
    let canton_id = req.params.canton_id;
    console.log("Canton en la llamada de parroquias...");
    console.log(canton_id);
    parroquiaRestClient.getParroquia(canton_id, function (responseCode, data) {
        if (responseCode == 200) {
            return res.status(responseCode).json({
                code: responseCode,
                title: "Successfully retrieving of parroquia data",
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
