var restUrl = require('./../config/rest-api-url');
var Client = require("node-rest-client").Client;

////////////////// MULTIPART/FORM-DATA REQUESTS /////////////////////
var request = require("request");


///////////////////////////////////////////METODO GET DE EXITOSO RESPUESTA/////////////////////////////
var getExitoso = function (parametros, token, callback) {
    ///////////////////////////////////////////NODE-REST-CLIENT////////////////////////////////////////
    var client = new Client();
    ///////////////////////////////////////////DATOS DEL LA PAGINA DE PAYPAL GET///////////////////////
    var payerID = parametros.params.PayerID;
    var paymentId = parametros.params.paymentId;

    ///////////////////////////////////////////CONSUMO DE GET DEL SERVIDOR DE RUBY (PATTY)/////////////
    var get = client.get(restUrl.checkout + '/checkout?paymentId=' + paymentId + '&token=' + token + '&PayerID=' + payerID + '', function (data, response) {
        callback(response.statusCode, data);
    });

    get.on("error", function (err) {
        console.log(err);
        callback(500, err.code);
    });
};
///////////////////////////////////////////////////////////////////////////////////////////////////////


///////////////////////////////////////////METODO GET DE CANCELADO RESPUESTA///////////////////////////
var getCancelado = function (callback) {
    ///////////////////////////////////////////METODO GET DE CANCELADO SERVIDOR PATTY///////////////////////////
    var get = client.get(restUrl.cancelado, args, function (data, response) {
        callback(response.statusCode, data);
    });

    get.on("error", function (err) {
        console.log(err);
        callback(500, err.code);
    });
};
///////////////////////////////////////////////////////////////////////////////////////////////////////


///////////////////////////////////////////METODO POST DE PAGO POR LA PLATAFORMA///////////////////////
var postPay = function (body, token, callback) {
    var total = body.total * 100;
    var client = new Client();
    var args = {
        data: {
            "shopping_id": body.ci,
            "total": total,
            "items": [{
                "name": "PAGO DEL SERVICIO " + body.empresa + "",
                "sku": body.factura,
                "price": body.total,
                "currency": "USD",
                "quantity": 1
            }],
            "return_url": restUrl.exitoso,
            "cancel_url": restUrl.cancelado
        },
        headers: {
            "Content-Type": "application/json",
            "Authorization": "Token " + token
        }
    }

    var post = client.post(restUrl.pay, args, function (data, response) {
        callback(response.statusCode, data);
    });

    post.on("error", function (err) {
        console.log("data", " cancelado");
        console.log(err);
        callback(500, err.code);
    });
};
///////////////////////////////////////////////////////////////////////////////////////////////////////


///////////////////////////////////////////METODO POST DE PAGO POR TARJETA////////////////////////////
var postCards = function (body, token, callback) {
    var total = body.total * 100;
    var client = new Client();
    var args = {
        data: {
            "tarjeta": {
                "email": body.email,
                "number": body.numero,
                "expire_month": body.mes,
                "expire_year": body.anio,
                "cvv2": body.cvv
            },
            "productos": {
                "total": total,
                "items": [{
                    "name": "PAGO DEL SERVICIO " + body.empresa + "",
                    "sku": body.factura,
                    "price": body.total,
                    "currency": "USD",
                    "quantity": 1
                }],
                "return_url": restUrl.exitoso,
                "cancel_url": restUrl.cancelado
            }
        },
        headers: {
            "Content-Type": "application/json",
            "Authorization": "Token " + token
        }
    }
    var post = client.post(restUrl.card, args, function (data, response) {
        callback(response.statusCode, data);
    });

    post.on("error", function (err) {
        callback(500, err.code);
    });
};
//////////////////////////////////////////////////////////////////////////////////////////////////////

module.exports = {
    getExitoso: getExitoso,
    postPay: postPay,
    postCards: postCards,
    getCancelado: getCancelado
}