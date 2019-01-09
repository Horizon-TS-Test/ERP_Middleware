var express = require('express');
var router = express.Router();

var actionRestClient = require('./../rest-client/action-client');
var actionTypes = require('./../const/action-types');

var notifRestClient = require('./../rest-client/notification-client');
var wepushClient = require('./../rest-client/webpush-client');

router.post('/', function (req, res, next) {
  let token = req.session.key.token;
  let relevanceType = actionTypes.relevance;
  req.body.action_type = relevanceType;
  
  actionRestClient.postAction(req.body, null, token, function (responseCode, data) {
    if (responseCode == 201 || responseCode == 200) {
      let userNotif = data.receivers;
      let ownerPubName, ownerComName;
      let ownerPubId, ownerComId;

      if (req.body.active === true && userNotif.length > 0) {
        if (data.pub_owner) {
          ownerPubName = data.pub_owner.user_name;
          ownerPubId = data.pub_owner.user_id;
        }
        if (data.action_parent_owner) {
          ownerComName = data.action_parent_owner.user_name;
          ownerComId = data.action_parent_owner.id;
        }

        let receivers = [];
        let userEmitter = req.body.userName;
        let emitterId = req.body.userId;
        let emitterImage = req.body.userImage;
        let title = 'Lukask, expresa tu opinión';
        let content;
        let defaultUrl = '/activity?pubId=' + data.publication + ((data.action_parent) ? '&comId=' + data.action_parent : '');

        for (let user of userNotif) {
          if (user.fields.owner_publication == true) {
            if (req.body.action_parent) {
              if (user.fields.owner_comment == true) {
                content = userEmitter + " ha apoyado tu comentario de tu publicación";
              }
              else if (emitterId == ownerComId) {
                content = userEmitter + " ha apoyado su comentario de tu publicación";
              }
              else {
                content = userEmitter + " ha apoyado el comentario de " + ownerComName + " de tu publicación";
              }
            }
            else {
              content = userEmitter + " ha apoyado tu publicación";
            }
          }
          else {
            if (emitterId == ownerPubId) {
              if (req.body.action_parent) {
                if (emitterId == ownerComId) {
                  content = userEmitter + " también ha apoyado su comentario de su publicación";
                }
                else if (user.fields.owner_comment == true) {
                  content = userEmitter + " ha apoyado tu comentario de su publicación";
                }
                else {
                  content = userEmitter + " también ha apoyado el comentario de " + ownerComName + " de su publicación";
                }
              }
              else {
                content = userEmitter + " también ha apoyado su publicación";
              }
            }
            else {
              if (req.body.action_parent) {
                if (emitterId == ownerComId) {
                  content = userEmitter + " también ha apoyado su comentario de la publicación de " + ownerPubName;
                }
                else if (user.fields.owner_comment == true) {
                  content = userEmitter + " ha apoyado tu comentario de la publicación de " + ownerPubName;
                }
                else if (ownerPubName === ownerComName) {
                  content = userEmitter + " también ha apoyado el comentario de " + ownerComName + " de su publicación";
                }
                else {
                  content = userEmitter + " también ha apoyado el comentario de " + ownerComName + " de la publicación de " + ownerPubName;
                }
              }
              else {
                content = userEmitter + " también ha apoyado la publicación de " + ownerPubName;
              }
            }
          }

          receivers[receivers.length] = {
            user_img: emitterImage,
            user_id: user.fields.user_register,
            title: title,
            content: content,
            open_url: defaultUrl,
            actions: null
          };
        }

        notifRestClient.postNotifications(title, req.body.date, defaultUrl, receivers, token, function (notCode, notData) {
          console.log(notCode, notData);
        });

        wepushClient.notify(receivers, function (resCode, notifData) {
          console.log(resCode, notifData);
        });
      }

      return res.status(responseCode).json({
        code: responseCode,
        title: "Action has been created successfully",
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

module.exports = router;
