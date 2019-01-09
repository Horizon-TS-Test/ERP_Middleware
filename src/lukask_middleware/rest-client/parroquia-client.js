var restUrl = require('./../config/rest-api-url');
var Client = require("node-rest-client").Client;

var getParroquia = function (canton_id, callback) {
    ///////////////////////////////////////////NODE-REST-CLIENT///////////////////////////////////////
    console.log("En el midle************************************************");
    console.log(restUrl.parroquia+ "?canton=" + canton_id);
    
    var client = new Client();

    //GET METHOD:
    var args = {
        headers: {
            "Content-Type": "application/json"
        }
    }

    var get = client.get(restUrl.parroquia + "?canton=" + canton_id, args, function (data, response) {
        console.log("Datos de la base de datos....!!!!!!!!!!");
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
    getParroquia: getParroquia,
}