var restUrl = require('./../config/rest-api-url');

var Client = require('node-rest-client').Client;

var restLogin = function (username, password, callback) {
    ///////////////////////////////////////////NODE-REST-CLIENT///////////////////////////////////////
    var client = new Client();

    //POST METHOD:
    var args = {
        data: {
        "username": username,
        "password": password
        },
        headers: {
            "Content-Type": "application/json",
        }
    }

    var post = client.post(restUrl.login, args, function(data, response) {
        callback(response.statusCode, data);
    });

    post.on("error", function(err){
        callback(500, err.code);
    });
    ////

    ///////////////////////////////////////////////////////////////////////////////////////////////////////
}

module.exports = {
    responseLogin: restLogin
}