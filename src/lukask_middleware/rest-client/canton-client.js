var restUrl = require('./../config/rest-api-url');
var Client = require("node-rest-client").Client;

var getCanton = function (provincia_id, callback) {
    ///////////////////////////////////////////NODE-REST-CLIENT///////////////////////////////////////
    var client = new Client();

    //GET METHOD:
    var args = {
        headers: {
            "Content-Type": "application/json"
        }
    }
    console.log("Llamando desde canton client ");
    console.log(restUrl.canton + "?province=" + provincia_id);
    var get = client.get(restUrl.canton + "?province=" + provincia_id, args, function (data, response) {
        console.log(data);
        callback(response.statusCode, data);
    });

    get.on("error", function (err) {
        console.log(err);
        callback(500, err.code);
    });
    ///////////////////////////////////////////////////////////////////////////////////////////////////////
}

module.exports = {
    getCanton: getCanton,
}