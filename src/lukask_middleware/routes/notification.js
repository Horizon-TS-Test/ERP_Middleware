var express = require('express');
var router = express.Router();

var notificationRestClient = require('./../rest-client/notification-client');

router.get('/', function (req, res, next) {
    let token = req.session.key.token;
    let receiver = (req.query.receiver) ? req.query.receiver : null;
    let limit = (req.query.limit) ? req.query.limit : null;
    let offset = (req.query.offset) ? req.query.offset : null;

    notificationRestClient.getNotifications(receiver, limit, offset, token, function (responseCode, data) {
        if (responseCode == 200) {
            return res.status(responseCode).json({
                code: responseCode,
                title: "Successfully retrieving of notification data with pagination",
                notifs: data
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
