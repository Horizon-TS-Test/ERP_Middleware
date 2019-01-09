/**
 * Autor: Dennys Moyón
 */
var express = require('express');
var router = express.Router();
var mediaRestClient = require('./../rest-client/media-client');
var servers = require('../config/servers');
var credentials = require('../config/credentials');
var multer = require("multer");
var ftpStorage = require("multer-ftp");
var ftpClient = require("ftp");


/**********************************************
 * WEBSOCKET CLIENT PARA ENVIAR UNA ACTUALIZACION DE LOS MEDIOS DE UNA PUBLICACION
 **********************************************/
//////////////////////////////////////////////////////////////////////////////////
var WebSocket = require('ws');
var ws = new WebSocket('ws://' + servers.backend_websocket + '/lukask-api');

/**********FTP SAVE VIDEO ************************/
var  upload = multer({
     storage : new ftpStorage({
        basepath : '/home/vagrant/',
        destination : function (req, file, options, callback){
            console.log("analiza o que ....");
            callback(null,  "medios_lukask/" + file.originalname + ".webm");
        },
        ftp : {
            host : servers.ftp_server,
            secure: false,
            user : credentials.userFtp,
            password : credentials.passwordFtp
        }
    })
}).array('media_file[]', 5);

router.post('/',function(req, res, next){
    try{
        //console.log("req...", req);
        upload(req, res, function(err){
            
            if(err){
                return res.status(500).json({
                    code : 500,
                    title : 'ERROR AL GUARDAR EL VIDEO EN SERVIDOR FTP',
                    data : err
                });
            }
            let token = req.session.key.token;
            
            mediaRestClient.postMedia(req.body.id_publication, req.files, token, (statusCode, data) =>{
                if(statusCode == 201){
                    /***
                     * consulta de datos soket
                     */
                   /* var msg = {
                        stream: "publication",
                        payload: {
                            action: "custom_update",
                            pk: req.body.idPublication,
                            data: {  }
                        }
                    }
                    ws.send(JSON.stringify(msg));

                    ws.onmessage = function (message) {
                        // SOCKET.IO CLIENTS LOGGED CONTROL:
                        //REF: https://stackoverflow.com/questions/35249770/how-to-get-all-the-sockets-connected-to-socket-io
                        Object.keys(req.io.sockets.sockets).forEach(function (id) {
                        console.log("FROM PUB: Sending data to socket with ID: ", id)  // socketId
                        if (req.io.sockets.connected[id].request.session.key) {
                            //REF: https://stackoverflow.com/questions/8281382/socket-send-outside-of-io-sockets-on
                            req.io.sockets.connected[id].emit("backend-rules", JSON.parse(message.data));
                        }
                        })
                        ////
                    }*/
                    return res.status(statusCode).json({
                        code : statusCode,
                        title : 'The media has been successfully added',
                        data : data
                    });
                }
                return res.status(statusCode).json({
                    code : statusCode,
                    title : "an error has ocurred",
                    error : data
                });
            });

        });
    }catch(error){
       console.log('<!ERROR AL EN EL PROCESO DE GUARDAR EL ARCHIVO>', error);
    }
});

router.get('/', function(req, res, next){
    var client = new ftpClient();
    let pathVideo  = req.query.pathmedia.replace(/ /g, "+");

    //EVENTO QUE ESCUCHA LA CONECCION DEL SERVIDOR
    client.on('ready',function(){
        client.get(pathVideo, (err, stream) =>{
           try{
               if(err){
                   return res.status(500).send(err)
               }
               stream.once('close', function(){client.end();});
               res.setHeader("content-type", "video/webm");
               stream.pipe(res);

          }catch(err){
                res.status(500).send(err);
            }
        });
    });

    //CONECCION A SERVIDOR FTP
    client.connect({
        host : servers.ftp_server,
        port : 21,
        user : credentials.userFtp,
        password : credentials.passwordFtp
    });
});

module.exports = router;