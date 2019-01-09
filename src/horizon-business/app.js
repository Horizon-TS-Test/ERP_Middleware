var createError = require('http-errors');
var express = require('express');
var path = require('path');
var cookieParser = require('cookie-parser');
var logger = require('morgan');

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/**
 * --------------------------- GENERAL IMPORTS
 */
var serverURLS = require("./config/servers");
var wsURL = require("./config/backws");

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/**
 * --------------------------- USED TO STORE SESSION INSIDE REDIS SERVER
 */
var redis = require('redis');
var session = require('express-session');
var redisStore = require('connect-redis')(session);
var redisAuth = require('./config/redis_auth');

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/**
 * --------------------------- CRYPTO GENERATOR
 */
var cryptoGen = require('./tools/crypto-generator');

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/**
 * --------------------------- USED TO STORE SESSION INSIDE REDIS SERVER
 */
var secret = require('./config/secret');
const exp_time = 900;
//const exp_time = 60;
const def_exp_time = 86400;
const aux_prefij = 'auxex_';
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

/**
 * ////////USED TO STORE SESSION INSIDE REDIS SERVER://///////
 */
var redisClient = redis.createClient({ host: redisAuth.host, port: redisAuth.port, password: redisAuth.password });

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/**
 * --------------------------- ROUTES
 */
var indexRouter = require('./routes/index');
var usersRouter = require('./routes/users');
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

var app = express();
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/**
 * --------------------------- SOCKET.IO WITH EXPRESS GENERATOR:
 * REF: https://medium.com/@suhas_chitade/express-generator-with-socket-io-80464341e8ba
 */
var server = require("http").Server(app);
var io = require("socket.io")(server);

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/**
 * --------------------------- USED TO STORE SESSION INSIDE REDIS SERVER
 */
var sessionMiddleware = session({
  secret: secret.secret_key,
  //NEXT CREATES A NEW REDIS STORE:
  store: new redisStore({
    host: redisAuth.host,
    port: redisAuth.port,
    pass: redisAuth.password,
    client: redisClient,
    //NEXT LINE IS COMMENTED TO PUBLISH KEY EXPIRATION EVENT WITH A CUSTOM PROCEDURE
    //ttl: 9000 //seconds
  }),
  /////////////////////////////////
  saveUninitialized: false,
  resave: false
});
app.use(sessionMiddleware);
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

// view engine setup
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'hbs');

app.use(logger('dev'));
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: false, limit: '50mb' }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));
//TO ENSURE THE ACCESS TO NODE_MODULES FROM THE ROUTES:
app.use(express.static(path.join(__dirname, 'node_modules')));
////


////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/**
 * --------------------------- ENABLE CORS:
 */
//TO ENSURE OUR FRONT END CLIENT COULD REACH THIS MIDDLEWARE SERVER:
app.use(function (req, res, next) {
  res.setHeader('Access-Control-Allow-Origin', serverURLS.allow_origin);
  res.setHeader('Access-Control-Allow-Headers', 'Origin, Content-Length, X-Requested-With, Content-Type, Accept, X-Access-Token, Pass-Key');
  res.setHeader('Access-Control-Allow-Methods', 'DELETE, GET, POST, PUT, PATCH');
  res.setHeader('Access-Control-Allow-Credentials', 'true');

  //PREFLIGHT REQUEST HACKED:
  //REF: https://vinaygopinath.me/blog/tech/enable-cors-with-pre-flight/
  if ('OPTIONS' == req.method) {
    res.sendStatus(200);
  } else {
    next();
  }
});

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/**
 * --------------------------- MIDDLEWARE METHOD USED TO ENSURE USERS MUST BE LOGGED FIRST:
 */
app.use(function (req, res, next) {
  //REF: https://stackoverflow.com/questions/12525928/how-to-get-request-path-with-express-req-object
  if (req.originalUrl.indexOf('images') === -1 && req.originalUrl.indexOf('parroquia') === -1 && req.originalUrl.indexOf('canton') === -1 && req.originalUrl.indexOf('province') === -1 && req.originalUrl.indexOf('signIn') === -1 && req.originalUrl.indexOf('login') === -1 && req.originalUrl.indexOf('logout') === -1 && req.originalUrl.indexOf('/media/?pathmedia') === -1) {
    console.log("Express sessions controling middleware");
    if (!req.session.key) {
      return res.status(401).json({
        code: 401,
        title: "Not Authenticated",
        data: "You must be logged first."
      });
    }

    let localEncrypted = req.session.key.crypto_user_id;
    if (!req.headers['x-access-token']) {
      return res.status(401).json({
        code: 401,
        title: "Not Authorized",
        data: "You must provide user credentials"
      });
    }
    //REF: https://scotch.io/tutorials/authenticate-a-node-js-api-with-json-web-tokens
    let userEncrypted = req.headers['x-access-token'];

    if (!(localEncrypted.content === userEncrypted.content && cryptoGen.decrypt(localEncrypted) === cryptoGen.decrypt(userEncrypted))) {
      return res.status(401).json({
        code: 401,
        title: "Not Authorized",
        data: "Invalid user credentials"
      });
    }
  }
  next();
});

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/**
 * --------------------------- SOCKET.IO MIDDLEWARE TO LINK EXPRESS STATUS AND SESSION WITH SOCKET.IO STATUS:
 */
io.use(function (socket, next) {
  sessionMiddleware(socket.request, {}, next);
});

io.use(function (socket, next) {
  console.log("Socket.io middleware!!");

  //REF: https://stackoverflow.com/questions/35249770/how-to-get-all-the-sockets-connected-to-socket-io
  Object.keys(io.sockets.sockets).forEach(function (id) {
    console.log("Socket ID: ", id);
  });

  if (!socket.request.session.key) {
    console.log("A client tried to connect without have logged first, now forcing logout");
    socket.force_logout = true;
  }
  else {
    console.log("Authenticated user has connected, Socket ID: ", socket.id);
  }

  next();
});

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/**
 * --------------------------- USING SOCKET.IO
 */
io.on("connection", function (socket) {
  if (socket.force_logout) {
    socket.emit('force_logout', 'You has been kicked from the server. Echo from server.');
    //REF: https://stackoverflow.com/questions/42064870/socket-io-disconnection-on-logout-and-network-out
    socket.disconnect();
  }

  socket.on("disconnect", function (data) {
    console.log("Socket has been disconnected: ", data);
  });
});

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/**
 * --------------------------- SOCKET WITH EXPRESS GENERATOR:
 */
//REF: https://medium.com/@suhas_chitade/express-generator-with-socket-io-80464341e8ba
//TO SHARE SOCKET INSTANCE TO EXPRESS ROUTES:
app.use(function (req, res, next) {
  req.io = io;
  next();
});

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/**
 * --------------------------- USING ROUTES:
 */
app.use('/', indexRouter);
app.use('/users', usersRouter);

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////


// catch 404 and forward to error handler
app.use(function (req, res, next) {
  next(createError(404));
});

// error handler
app.use(function (err, req, res, next) {
  // set locals, only providing error in development
  res.locals.message = err.message;
  res.locals.error = req.app.get('env') === 'development' ? err : {};

  // render the error page
  res.status(err.status || 500);
  res.render('error');
});


////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/**
 * --------------------------- REDIS PUB/SUB
 * USED TO HANDLE THE EXPIRATED KEYS WHICH CONTAINS THE COOKIE SESSIONS OF THE FRONTEND USERS AND THEN FORCE THEM TO LOGOUT:
 */
var pubsubClient = redis.createClient({ host: redisAuth.host, port: redisAuth.port, password: redisAuth.password });
var settingClient = redis.createClient({ host: redisAuth.host, port: redisAuth.port, password: redisAuth.password });
var gettingClient = redis.createClient({ host: redisAuth.host, port: redisAuth.port, password: redisAuth.password });

var EVENT_SET = '__keyevent@0__:set';
var EVENT_DEL = '__keyevent@0__:del';
var EVENT_EXPIRED = '__keyevent@0__:expired';

//__keyevent@0__:expired EVENT CONFIGURATION ON REDIS:
pubsubClient.config("SET", "notify-keyspace-events", "Ex");
////
//__keyevent@0__:set AND __keyevent@0__:del EVENTS CONFIGURATION ON REDIS:
pubsubClient.config("SET", "notify-keyspace-events", "KEA");
////
pubsubClient.on('message', function (channel, key) {
  switch (channel) {
    case EVENT_EXPIRED:
      console.log('Key "' + key + '" expired!');
      let indi = 0;

      if (key.indexOf(aux_prefij) !== -1) {
        gettingClient.get(key.replace(aux_prefij, ""), function (err, reply) {
          let keyData = JSON.parse(reply);
          if (keyData.key) {
            //SEARCHING FOR SOCKET WITH EXPIRED USER ID TO NOTIFY ABOUT SESSION EXPIRATION:
            console.log("N sockets: ", Object.keys(io.sockets.sockets).length);
            //REF: https://stackoverflow.com/questions/35249770/how-to-get-all-the-sockets-connected-to-socket-io
            Object.keys(io.sockets.sockets).forEach(function (id) {
              if (io.sockets.connected[id].request.session.key) {
                if (io.sockets.connected[id].request.session.key.crypto_user_id === keyData.key.crypto_user_id) {
                  console.log("Session expired. Socket ID: ", id);
                  io.sockets.connected[id].emit('force_logout', 'Your session has expired. Echo from server.');
                  //REF: https://stackoverflow.com/questions/42064870/socket-io-disconnection-on-logout-and-network-out
                  io.sockets.connected[id].disconnect();
                  settingClient.del(key.replace(aux_prefij, ''));
                  indi = 1;
                }
              }
            });
            if (indi == 0) {
              settingClient.del(key.replace(aux_prefij, ''));
            }
            ////
          }
        });
      }
      break;
  }
});

pubsubClient.subscribe(EVENT_SET, EVENT_DEL, EVENT_EXPIRED);


////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/**
 * //////////USING WEBSOCKET CLIENT OF PYTHON CONNECTION//////////
 */
var WebSocketClient = require('websocket').client;

var client = new WebSocketClient();

client.on('connectFailed', function (error) {
  console.log('Channels API Websocket Connect Error: ' + error.toString());
});

client.on('connect', function (connection) {
  console.log('Channels API Websocket client connected');

  connection.on('error', function (error) {
    console.log("Channels API Websocket Connection Error: " + error.toString());
  });

  //-------------------------------SUBSCRIPTIONS:---------------------------------
  /*var msg = {
    stream: "publication",
    payload: {
      action: "subscribe",
      data: {
        action: "create"
      }
    }
  };

  connection.send(JSON.stringify(msg));

  var msg = {
    stream: "publication",
    payload: {
      action: "subscribe",
      data: {
        action: "update"
      }
    }
  };

  connection.send(JSON.stringify(msg));

  msg = {
    stream: "publication",
    payload: {
      action: "subscribe",
      data: {
        action: "delete"
      }
    }
  }
  connection.send(JSON.stringify(msg));*/
  //---------------------------------------------------------------------------------------------------------

  connection.on('message', function (message) {
    if (message.type === 'utf8') {
      console.log("Channels API Websocket data received: ", JSON.parse(message.utf8Data));
      // SOCKET.IO CLIENTS LOGGED CONTROL:
      //REF: https://stackoverflow.com/questions/35249770/how-to-get-all-the-sockets-connected-to-socket-io
      Object.keys(io.sockets.sockets).forEach(function (id) {
        console.log("Sending data to socket with ID: ", id)  // socketId
        if (io.sockets.connected[id].request.session.key) {
          //REF: https://stackoverflow.com/questions/8281382/socket-send-outside-of-io-sockets-on
          io.sockets.connected[id].emit("backend-rules", JSON.parse(message.utf8Data));
        }
      })
      ////
    }
  });

  connection.on('close', function () {
    console.log('Channels API Websocket echo-protocol Connection Closed');
  });
});

client.connect('ws://' + wsURL.backWsURL, "", "http://" + serverURLS.backend_ws);


////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/**
 * --------------------------- SOCKET WITH EXPRESS GENERATOR
 * REF: https://medium.com/@suhas_chitade/express-generator-with-socket-io-80464341e8ba
 */
module.exports = { app: app, server: server };

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////