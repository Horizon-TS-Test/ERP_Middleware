var express = require('express');
var router = express.Router();
var eersaReclamoCli = require("../rest-client/eersa/reclamo-client");
var postClaim = require('./../controllers/pub-controller');

/////////////////////// FILE UPLOAD ////////////////////////
const pubMediaDest = 'public/images/pubs';
//REF: https://www.npmjs.com/package/multer
var multer = require("multer");
var storage = multer.diskStorage(
    {
        destination: function (req, file, cb) {
            cb(null, pubMediaDest)
        },
        filename: function (req, file, cb) {
            cb(null, req.body.userId + '-' + Date.now() + ".png")
        }
    }
);
var upload = multer({ storage: storage });
////////////////////////////////////////////////////////////

router.post('/claim', upload.array('media_files[]', 5), (req, res, next) => {
    var token = req.session.key.token;

    let claimData = {
        ncuenta: req.body.nCuenta,
        nmedidor: req.body.nMedidor,
        nposte: req.body.nPoste,
        cliente: req.body.cliente,
        cedula: req.body.cedula,
        telefono: req.body.telefono,
        celular: req.body.celular,
        email: req.body.email,
        calle: req.body.calle,
        idtipo: req.body.idTipo,
        idbarrio: req.body.idBarrio,
        referencia: req.body.referencia,
        areclamo: req.body.detalleReclamo
    }

    eersaReclamoCli.insertReclamo(claimData, function (statusCode, data) {
        if (statusCode == 201) {
            let claimId = data;
            req.body.eersaClaimId = claimId;
            postClaim.postClaim(req.body, req.files, token, req.io, function (pubData) {
                if (pubData.isError) {
                    return res.status(pubData.code).json({
                        code: pubData.code,
                        title: pubData.title,
                        showFront: pubData.showMessage,
                        error: pubData.data
                    });
                }

                return res.status(pubData.code).json({
                    code: pubData.code,
                    title: pubData.title,
                    data: pubData.data
                });
            });
        }
        else {
            return res.status(statusCode).json({
                code: statusCode,
                title: "An error has occured",
                error: data
            });
        }
    });
});

module.exports = router;