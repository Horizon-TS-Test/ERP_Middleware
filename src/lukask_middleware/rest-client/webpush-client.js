var webpush = require('./../config/push-api');
var Client = require("node-rest-client").Client;
var Config = require("../config/credentials")

var notify = function (receivers, callback) {
    ///////////////////////////////////////////NODE-REST-CLIENT///////////////////////////////////////
    var client = new Client();

    //POST METHOD:
    var args = {
        data: {
            "receivers": receivers
        },
        headers: {
            "Content-Type": "application/json",
            "Authorization": "Token " + Config.push_cli_token
        }
    }

    var post = client.post(webpush.notification, args, function (data, response) {
        callback(response.statusCode, data);
    });

    post.on("error", function (err) {
        callback(500, err.code);
    });
    ///////////////////////////////////////////////////////////////////////////////////////////////////////
}

var subscribe = function (body, callback) {
    ///////////////////////////////////////////NODE-REST-CLIENT///////////////////////////////////////
    var client = new Client();

    //GET METHOD:
    var args = {
        data: body,
        headers: {
            "Content-Type": "application/json",
            "Authorization": "Token " + Config.push_cli_token
        }
    }

    post = client.post(webpush.subscribe, args, function (data, response) {
        callback(response.statusCode, data);
    });

    post.on("error", function (err) {
        console.log(err);
        callback(500, err);
    });
    ////

    ///////////////////////////////////////////////////////////////////////////////////////////////////////
}

var unsubscribe = function (body, callback) {
    ///////////////////////////////////////////NODE-REST-CLIENT///////////////////////////////////////
    var client = new Client();

    //POST METHOD:
    var args = {
        data: body,
        headers: {
            "Content-Type": "application/json",
            "Authorization": "Token " + Config.push_cli_token
        }
    }

    var post = client.post(webpush.unsubscribe, args, function (data, response) {
        callback(response.statusCode, data);
    });

    post.on("error", function (err) {
        console.log(err);
        callback(500, err);
    });
    ////

    ///////////////////////////////////////////////////////////////////////////////////////////////////////
}


var token = function (req, res) {
    ///////////////////////////////////////////NODE-REST-CLIENT///////////////////////////////////////
    var client = new Client();

    //POST METHOD:
    var args = {
        data: {
            "receivers": receivers
        },
        headers: {
            "Content-Type": "application/json"
        }
    }

    var post = client.post(webpush.notification, args, function (data, response) {
        callback(response.statusCode, data);
    });

    post.on("error", function (err) {
        callback(500, err.code);
    });
    ///////////////////////////////////////////////////////////////////////////////////////////////////////
}

module.exports = {
    notify: notify,
    subscribe: subscribe,
    unsubscribe: unsubscribe,
}