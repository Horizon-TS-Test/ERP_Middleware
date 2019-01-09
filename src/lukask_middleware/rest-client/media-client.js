/**
 * Autor: Dennys Moyón
 */
var resourceBackUrl = require('./../config/rest-api-url');
var request = require('request');

var postMedia = function(idPub, mediosArray, token, callback){
    var rData = request.post(
        {
            url: resourceBackUrl.media,
            headers:{
                "Content-Type" : "application/x-www-form-urlencoded",
                "Authorization" : "Token "  + token
            }
        }, function optionalCallback(err, httpResponse, data){
              if(err){
                  callback(httpResponse.statusCode, err);
              }
              if(httpResponse.statusCode == 201){
                  callback(httpResponse.statusCode, JSON.parse(data));
              }else{
                  callback(httpResponse.statusCode, data);
              }
        });
    
    //DATOS PARA EL NUEVO ARCHIVO MULTIMEDIA
    var form = rData.form(); 

    form.append('publication', idPub);
    if(mediosArray){
        for(let i = 0; i < mediosArray.length; i++){
            let nameFile = mediosArray[i].originalname.length > 49 ? mediosArray[i].originalname.substring(0, 48) : mediosArray[i].originalname;
            console.log("nameFile", nameFile)
            form.append('multimedia['+i+']name_file', nameFile);
            form.append('multimedia['+i+']format_multimedia', 'VD');
            form.append('multimedia['+i+']description_file', nameFile);
            form.append('multimedia['+i+']media_path', mediosArray[i].path);
        }
    }
}

module.exports = {
    postMedia : postMedia
}