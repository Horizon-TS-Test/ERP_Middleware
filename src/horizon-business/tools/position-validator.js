'use strict';

/**
 * Función que determina si la distancia es o no menor a un criterio en este caso menor a 10mtr
 * @param {Lista de publicaciones } lista 
 * @param {Latitud de la posicion que va a ser registrada } latitud 
 * @param {Longitud de la posicion que va a ser registrada} longitud 
 * @param {Tipo de la publicacion  } tipoP 
 */
function determinePosition(lista, latitud, longitud, tipoP) {
  for (let dato in lista) {
    var distancia = getDistanceToCoords(latitud, longitud, lista[dato].latitude, lista[dato].length);
    if (distancia < 10 && tipoP == lista[dato].type_publication) {
      return false;
    }
  }
  return true;
}


/**
 * Funcion que calcula la distancia de dos puntos dado su latitud y longitud
 * @param {Latitud posicion uno} lat1 
 * @param {Longitud posicion uno} lon1 
 * @param {Latitud posicion dos} lat2 
 * @param {Longitud posicion dos} lon2 
 */
function getDistanceToCoords(lat1, lon1, lat2, lon2) {
  function _deg2rad(deg) {
    return deg * (Math.PI / 180)
  }
  var R = 6371; // Radius of the earth in km 3963.191 in milles
  var dLat = _deg2rad(lat2 - lat1);  // deg2rad below
  var dLon = _deg2rad(lon2 - lon1);
  var a =
    Math.sin(dLat / 2) * Math.sin(dLat / 2) +
    Math.cos(_deg2rad(lat1)) * Math.cos(_deg2rad(lat2)) *
    Math.sin(dLon / 2) * Math.sin(dLon / 2);
  var c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
  var d = R * c; // Distance in km
  d = d * 1000;
  console.log(d, "mt");
  return d.toFixed(3);
}

module.exports = { determinePosition };