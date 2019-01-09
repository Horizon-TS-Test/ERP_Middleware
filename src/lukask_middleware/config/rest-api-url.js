var servers = require('./servers');

module.exports = {
    pub: servers.backend + '/lukask-api/publication/',
    action: servers.backend + '/lukask-api/actionPub/',
    quejaType: servers.backend + '/lukask-api/typePub/',
    login: servers.backend + '/lukask-api/login/',
    user: servers.backend + '/lukask-api/userProfile/',
    getNotif: servers.backend + '/lukask-api/notification_received/',
    postNotif: servers.backend + '/lukask-api/notification/',
    pay: servers.payment + '/pagar',
    card: servers.payment + '/card',
    exitoso: servers.self + 'payment/exitoso',
    checkout: servers.payment + '',
    cancelado: servers.payment + '/cancelado',
    province: servers.backend + '/lukask-api/province/',
    canton: servers.backend + '/lukask-api/canton/',
    parroquia: servers.backend + '/lukask-api/parish/',
    media: servers.backend + '/lukask-api/gestion_media'
}