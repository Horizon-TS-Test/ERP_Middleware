var express = require('express');
var router = express.Router();
var paymentRestClient = require('./../rest-client/payments-client');
var redis = require('redis');
var redisAuth = require('./../config/redis_auth');


/////////////////////// RUTA EXITOSO DE PAYPAL ////////////////////////
router.get('/exitoso', function (req, res, next) {
  /////////////////////// PARAMETROS PARA REIZAR LA OPERACION//////////
  var parametros = {
    params: {
      "paymentId": req.query.paymentId,
      "PayerID": req.query.PayerID,
      "token": req.query.token
    }
  };
  var token = req.session.key.token;
  var paypalsecret = 'pay-';
  var date = new Date();

  paymentRestClient.getExitoso(parametros, token, function (responseCode, data) {
    /////////////////////// CREACION DE USUARIO REDIS///////////////////
    var payClient = redis.createClient({
      host: redisAuth.host,
      port: redisAuth.port,
      password: redisAuth.password
    });
    console.log("req.session.crypto_user_id", req.session.crypto_user_id);
    var redisData = {
      crypto_user_id: req.session.key.crypto_user_id,
      paypalData: data
    }
    payClient.set(paypalsecret, JSON.stringify(redisData));
    if (responseCode == 200) {
        return res.redirect('http://127.0.0.1:4200/inicio');
    }
    return res.status(responseCode).json({
      code: responseCode,
      title: "An error has occurred",
      error: data
    });
  });
});
//////////////////////////////////////////////////////////////////////


/////////////////////// RUTA CANCELADO DE PAYPAL /////////////////////
router.get('/cancelado', function (req, res, next) {
  let body = req.body;
  let token = req.session.key.token;
  paymentRestClient.getCancelado(body, token, function (responseCode, data) {
    if (responseCode == 200) {
      return res.redirect('http://127.0.0.1:4200/inicio');
    }
    return res.status(responseCode).json({
      code: responseCode,
      title: "An error has occurred",
      error: data
    });
  });
});
/////////////////////////////////////////////////////////////////////

/////////////////////// RUTA PAGOS CON PAYPAL ///////////////////////
router.post('/pay', function (req, res, next) {
  console.log("LLego al router");
  var token = req.session.key.token;
  
  paymentRestClient.postPay(req.body, token, function (responseCode, data) {
    if (responseCode == 200) {
      return res.status(responseCode).json({
        code: responseCode,
        title: "Sus datos successfully",
        data: data
      });
      
    }
    return res.status(responseCode).json({
      code: responseCode,
      title: "An error has occurred",
      error: data
    });
  });
});
////////////////////////////////////////////////////////////////////


/////////////////////// RUTA PAGOS CON TARJETA PAYPAL /////////////
router.post('/card', function (req, res, next) {
  var token = req.session.key.token;
  paymentRestClient.postCards(req.body, token, function (responseCode, data) {
    if (responseCode == 200) {
      return res.status(responseCode).json({
        code: responseCode,
        title: "Sus datos successfully",
        data: data
      });
    } 
    if  (responseCode == 422) {
      console.log("llego el error", data);
      return res.status(responseCode).json({
        code: responseCode,
        title: "An error has occurred",
        data: data
      });
    }
  });
});
//////////////////////////////////////////////////////////////////


module.exports = router;