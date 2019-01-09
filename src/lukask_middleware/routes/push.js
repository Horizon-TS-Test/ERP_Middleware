var express = require('express');
var router = express.Router();

var wepushClient = require('./../rest-client/webpush-client');

router.post('/subscribe', function (req, res, next) {
    wepushClient.subscribe(req.body, function (responseCode, data) {
        if (responseCode == 200) {
            return res.status(responseCode).json({
                code: responseCode,
                title: "Successfully calling of subscribe endpoint",
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

router.post('/unsubscribe', function (req, res, next) {
    wepushClient.unsubscribe(req.body, function (responseCode, data) {
        if (responseCode == 200) {
            return res.status(responseCode).json({
                code: responseCode,
                title: "Successfully calling of unsubscribe endpoint",
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
