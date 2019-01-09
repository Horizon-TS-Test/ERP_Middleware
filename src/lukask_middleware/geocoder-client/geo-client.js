var NodeGeocoder = require('node-geocoder');
var googleOptions = require("../config/google-maps-data");

var getCity = function (latitude, longitude, callback) {
    var cityPromise = new Promise((resolve, reject) => {

        var options = googleOptions.options;
        var geocoder = NodeGeocoder(options);
        var Local = { lat: latitude, lon: longitude };
        var location = "";

        geocoder.reverse(Local, (err, res) => {
            if (err) {
                console.log("Error" + err);
                resolve('Riobamba');
            }
            location = res[0].city;
            resolve(location);
        });
    });

    callback(cityPromise);
}

module.exports = {
    getCity: getCity
}