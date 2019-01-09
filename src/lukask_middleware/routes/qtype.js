var express = require('express');
var router = express.Router();

var qTypeRestClient = require('./../rest-client/qtype-client');

router.get('/', function (req, res, next) {
    let token = req.session.key.token;

    qTypeRestClient.getQuejaType(token, function (responseCode, data) {
        if (responseCode == 200) {
            return res.status(responseCode).json({
                code: responseCode,
                title: "Successfully retrieving of queja Type data",
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
