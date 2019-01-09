var restUrl = require('./../config/rest-api-url');

var Client = require("node-rest-client").Client;

var getNotifications = function (receiver, limit, offset, token, callback) {
    ///////////////////////////////////////////NODE-REST-CLIENT///////////////////////////////////////
    var client = new Client();
    var receiverFilter = (receiver) ? "?user_received=" + receiver : "";
    var limitFilter = (limit) ? "&limit=" + limit : "";
    var offsetFilter = (offset) ? "&offset=" + offset : "";

    var queryFilter = receiverFilter + limitFilter + offsetFilter;
    var nextPattern;

    var get;

    //GET METHOD:
    var args = {
        headers: {
            "Content-Type": "application/json",
            "Authorization": "Token " + token
        }
    }

    get = client.get(restUrl.getNotif + queryFilter, args, function (data, response) {
        if (data.next) {
            nextPattern = "&" + data.next.substring(data.next.indexOf("limit="), data.next.indexOf("&", data.next.indexOf("limit=")));
            nextPattern += "&" + data.next.substring(data.next.indexOf("offset="), data.next.indexOf("&", data.next.indexOf("offset=")));
            data.next = nextPattern;
        }
        console.log(data);
        callback(response.statusCode, data);
    });

    get.on("error", function (err) {
        console.log(err);
        callback(500, err);
    });
    ////

    ///////////////////////////////////////////////////////////////////////////////////////////////////////
}

var postNotifications = function (description, date, url, receivers, token, callback) {
    ///////////////////////////////////////////NODE-REST-CLIENT///////////////////////////////////////
    var client = new Client();

    //POST METHOD:
    let notifData = [];
    for (var i = 0; i < receivers.length; i++) {
        notifData[i] = {
            description_notif_rec: receivers[i].content,
            user_received: receivers[i].user_id
        };
    }
    console.log("notifData: ", notifData);

    var args = {
        data: {
            "description_notification": description,
            "date_generated": date,
            "url": url,
            "users_notificated": notifData
        },
        headers: {
            "Content-Type": "application/json",
            "Authorization": "Token " + token
        }
    }

    var post = client.post(restUrl.postNotif, args, function (data, response) {
        console.log(data);
        callback(response.statusCode, data);
    });

    post.on("error", function (err) {
        console.log(err);
        callback(500, err);
    });
    ////

    ///////////////////////////////////////////////////////////////////////////////////////////////////////
}

module.exports = {
    getNotifications: getNotifications,
    postNotifications: postNotifications
}