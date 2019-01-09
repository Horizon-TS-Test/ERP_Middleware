var restUrl = require('./../config/rest-api-url');

var Client = require("node-rest-client").Client;
////////////////// MULTIPART/FORM-DATA REQUESTS /////////////////////

var request = require('request');
////////////////////// FILE MANAGER ////////////////////////

var fs = require("fs");
////////////////////////////////////////////////////////////

var getUserProfile = function (userId, token, callback) {
    ///////////////////////////////////////////NODE-REST-CLIENT///////////////////////////////////////
    var client = new Client();

    //GET METHOD:
    var args = {
        headers: {
            "Content-Type": "application/json",
            "Authorization": "Token " + token
        }
    }

    var get = client.get(restUrl.user + userId + "/", args, function (data, response) {
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

var getUserSupporters = function (relevanceType, comRelevance, limit, offset, token, callback) {
    ///////////////////////////////////////////NODE-REST-CLIENT///////////////////////////////////////
    var client = new Client();
    var limitFilter = (limit) ? "?limit=" + limit : "";
    var offsetFilter = (limit && offset) ? "&offset=" + offset : "";
    var typeRelFilter = (comRelevance) ? "&usrRelCom=" + relevanceType : "&usrRelPub=" + relevanceType;

    var queryFilter = limitFilter + offsetFilter + typeRelFilter;
    var nextPattern;

    //GET METHOD:
    var args = {
        headers: {
            "Content-Type": "application/json",
            "Authorization": "Token " + token
        }
    }

    var get = client.get(restUrl.user + queryFilter, args, function (data, response) {
        if (data.next) {
            nextPattern = "&" + data.next.substring(data.next.indexOf("limit="), data.next.indexOf("&", data.next.indexOf("limit=")));
            nextPattern += "&" + data.next.substring(data.next.indexOf("offset="));
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

var patchUser = function (userId, body, mediaProfile, token, callback) {
    ////////////////////////////////// POST REQUEST //////////////////////////////////////
    var r = request.patch(
        {
            url: restUrl.user + userId + "/",
            headers: {
                "Content-Type": "application/x-www-form-urlencoded",
                "Authorization": "Token " + token
            }
        }, function optionalCallback(err, httpResponse, data) {
            if (err) {
                console.log('Error while making todo post request: ', err);
                callback(httpResponse.statusCode, err);
            }
            if (httpResponse.statusCode == 200) {
                console.log('User has been updted successfully, Server responded with: ', JSON.parse(data));
                callback(httpResponse.statusCode, JSON.parse(data));
            }
            else {
                console.log('Error while making user patch request: ', data);
                callback(httpResponse.statusCode, data);
            }
        });

    var form = r.form();

    form.append('id', body.id);
    form.append('email', body.email);
    form.append('person.age', body.age);
    form.append('person.identification_card', body.identification_card);
    form.append('person.name', body.name);
    form.append('person.last_name', body.last_name);
    form.append('person.telephone', body.telephone);
    form.append('person.address', body.address);
    form.append('person.cell_phone', body.cell_phone);
    form.append('person.birthdate', body.birthdate);
    form.append('person.province', body.province);
    form.append('person.canton', body.canton);
    form.append('person.parish', body.parroquia);
    form.append('is_active', body.is_active);

    if (mediaProfile) {
        form.append("profile_path", mediaProfile);
    }
    //////////////////////////////////////////////////////////////////////////////////////
}

/*Para un nuevo registro*/
var postUser = function (body, mediaProfile, callback) {
    ////////////////////////////////// POST REQUEST //////////////////////////////////////
    var r = request.post(
        {
            url: restUrl.user,
            headers: {
                "Content-Type": "application/x-www-form-urlencoded"
            }
        }, function optionalCallback(err, httpResponse, data) {
            if (err) {
                console.log('Error while making todo post request: ', err);
                callback(httpResponse.statusCode, err);
            }
            if (httpResponse.statusCode == 201) {
                console.log('User has been updted successfully, Server responded with: ', JSON.parse(data));
                callback(httpResponse.statusCode, JSON.parse(data));
            }
            else {
                console.log('Error while making user patch request: ', data);
                callback(httpResponse.statusCode, data);
            }
        });

    var form = r.form();
    //form.append('id', body.id);
    form.append('email', body.email);
    form.append('password', body.password);
    form.append('person.age', body.age + "");
    form.append('person.identification_card', body.identification_card);
    form.append('person.name', body.name);
    form.append('person.last_name', body.last_name);
    form.append('person.telephone', body.telephone);
    form.append('person.cell_phone', body.cell_phone);
    form.append('person.address', body.address);
    form.append('person.birthdate', body.birthdate);
    form.append('person.parish', body.parroquia);

    form.append('is_active', "true");
    /**/
    console.log("mediaProfile", mediaProfile);

    if (mediaProfile) {
        form.append("profile_path", mediaProfile);
    }
    //////////////////////////////////////////////////////////////////////////////////////
}

module.exports = {
    getUserProfile: getUserProfile,
    getUserSupporters: getUserSupporters,
    patchUser: patchUser,
    postUser: postUser,
}