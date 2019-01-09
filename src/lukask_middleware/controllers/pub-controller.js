var servers = require("../config/servers");
var pv = require("../tools/position-validator");
var geoClient = require("../geocoder-client/geo-client");
var publicationRestClient = require('./../rest-client/publication-client');

/*********************************************************************************
 * INICIALIZACIÓN DEL WEBSOCKET PARA ENVIAR LA ACTUALIZACIÓN DE UNA PUBLICACIÓN:
 ********************************************************************************/
//////////////////////////////////////////////////////////////////////////////////
var WebSocket = require('ws');
var ws = new WebSocket('ws://' + servers.backend_websocket + '/lukask-api');
//////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////

function defineMediaArray(files) {
    var dest, mediaArray = [];

    if (files && files.length > 0) {
        for (var i = 0; i < files.length; i++) {
            dest = files[i].path;
            dest = dest.replace("public/", "");

            mediaArray[mediaArray.length] = {
                mediaType: files[i].mimetype.indexOf("image") != -1 ? "IG" : "FL",
                mediaPath: "/" + dest,
                mediaName: dest.substring(dest.indexOf("/", dest.indexOf("pubs/")))
            };
        }
    } else {
        mediaArray[mediaArray.length] = {
            mediaType: "IG",
            mediaPath: "/images/default.jpg",
            mediaName: "default.jpg"
        };
    }
    return mediaArray;
}

/*********************************************************************************
 * METODO PARA VALIDAR QUE LA PUBLICACIÓN NO SE REPITA EN UN RANGO 10 METROS
 ********************************************************************************/
function validatePub(location, latitude, longitude, pubType, token, callback) {
    publicationRestClient.getPubFilter(token, location, function (responseCode, data) {
        if (responseCode == 200) {
            //Lista de pubicaciones registradas
            var pubFilterList = data.results;
            //Funcion que determina si esta apto para que la publicacion se pueda insertar o no 
            var respuesta = pv.determinePosition(pubFilterList, latitude, longitude, pubType);
            //Verdadero si se puede crear, Falso no se puede crear el registro
            callback(respuesta);
        }
        else {
            callback(true);
        }
    });
}
/*********************************************************************************
 ********************************************************************************/

var postClaim = function (body, files, token, io, callback) {
    let mediaArray = defineMediaArray(files);
    geoClient.getCity(body.latitude, body.longitude, (cityPromise) => {
        cityPromise.then((city) => {
            validatePub(city, body.latitude, body.longitude, body.type_publication, token, (isValid) => {
                /**** TEMPORAL: ****/
                isValid = true;
                /*******************/
                if (isValid) {
                    publicationRestClient.postPub(body, mediaArray, token, (responseCode, data) => {
                        if (responseCode == 201) {
                            var msg = {
                                stream: "publication",
                                payload: {
                                    action: "custom_create",
                                    pk: data.id_publication,
                                    data: {}
                                }
                            }
                            ws.send(JSON.stringify(msg));

                            ws.onmessage = function (message) {
                                // SOCKET.IO CLIENTS LOGGED CONTROL:
                                //REF: https://stackoverflow.com/questions/35249770/how-to-get-all-the-sockets-connected-to-socket-io
                                Object.keys(io.sockets.sockets).forEach(function (id) {
                                    console.log("FROM PUB: Sending data to socket with ID: ", id)  // socketId
                                    if (io.sockets.connected[id].request.session.key) {
                                        //REF: https://stackoverflow.com/questions/8281382/socket-send-outside-of-io-sockets-on
                                        io.sockets.connected[id].emit("backend-rules", JSON.parse(message.data));
                                    }
                                });
                                ////
                            }

                            let title = 'Claim has been created successfully'
                            callback({ code: responseCode, title: title, data: data, isError: false, showMessage: false });
                        } else {
                            let title = "An error has occurred";
                            callback({ code: responseCode, title: title, data: error, isError: true, showMessage: false });
                        }
                    });
                } else {
                    let title = 'An error has occurred';
                    let error = 'Ya existe una publicación del tipo seleccionado en la ubicación especificada';
                    callback({ code: 400, title: title, data: error, isError: true, showMessage: true });
                }
            });
        });
    });
};

var postPub = function (body, files, token, io, callback) {
    let mediaArray = defineMediaArray(files);

    publicationRestClient.postPub(body, mediaArray, token, (responseCode, data) => {
        if (responseCode == 201) {
            var msg = {
                stream: "publication",
                payload: {
                    action: "custom_create",
                    pk: data.id_publication,
                    data: {}
                }
            }
            ws.send(JSON.stringify(msg));

            ws.onmessage = function (message) {
                // SOCKET.IO CLIENTS LOGGED CONTROL:
                //REF: https://stackoverflow.com/questions/35249770/how-to-get-all-the-sockets-connected-to-socket-io
                Object.keys(io.sockets.sockets).forEach(function (id) {
                    console.log("FROM PUB: Sending data to socket with ID: ", id)  // socketId
                    if (io.sockets.connected[id].request.session.key) {
                        //REF: https://stackoverflow.com/questions/8281382/socket-send-outside-of-io-sockets-on
                        io.sockets.connected[id].emit("backend-rules", JSON.parse(message.data));
                    }
                });
                ////
            }

            let title = 'Publication has been created successfully'
            callback({ code: responseCode, title: title, data: data, isError: false, showMessage: false });
        }
        else {
            let title = "An error has occurred";
            callback({ code: responseCode, title: title, data: data, isError: true, showMessage: false });
        }
    });
};

module.exports = {
    postClaim: postClaim,
    postPub: postPub
}