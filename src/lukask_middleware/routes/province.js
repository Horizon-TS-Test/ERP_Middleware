var express = require('express');
var router = express.Router();

var provinceRestClient = require('./../rest-client/province-client');

router.get('/', function (req, res, next) {
    provinceRestClient.getProvince(function (responseCode, data) {
        if (responseCode == 200) {
            return res.status(responseCode).json({
                code: responseCode,
                title: "Successfully retrieving of province data",
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
