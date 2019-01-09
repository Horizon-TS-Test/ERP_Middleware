var soap = require('soap');
var eersaServer = require('../../config/eersa-server');

var insertReclamo = function (claimData, callback) {
    var url = eersaServer.eersaWS;

    soap.createClient(url, function (err, client) {
        if (client) {

            client.insertReclamo(claimData, function (err, result) {
                callback(result.statusCode ? result.statusCode : 201, result.statusCode ? 'COMMING ERROR FROM THE EERSA SERVER' : result.return);
            });
        }
        else {
            callback(404, 'Eersa server has gone down');
        }
    });
};


module.exports = {
    insertReclamo: insertReclamo
}