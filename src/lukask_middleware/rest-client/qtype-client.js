var restUrl = require('./../config/rest-api-url');
var Client = require("node-rest-client").Client;

var getQuejaType = function (token, callback) {
    ///////////////////////////////////////////NODE-REST-CLIENT///////////////////////////////////////
    var client = new Client();

    //GET METHOD:
    var args = {
        headers: {
            "Content-Type": "application/json",
            "Authorization": "Token " + token
        }
    }

    var get = client.get(restUrl.quejaType, args, function (data, response) {
        console.log(data);
        callback(response.statusCode, data);
    });

    get.on("error", function (err) {
        console.log(err);
        callback(500, err.code);
    });
    ////

    ///////////////////////////////////////////////////////////////////////////////////////////////////////
}

module.exports = {
    getQuejaType: getQuejaType,
}