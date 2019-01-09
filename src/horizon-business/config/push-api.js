var pushServer = 'http://192.168.1.5:3200';

module.exports = {
    notification: pushServer + '/notification',
    subscribe: pushServer + '/pubsub/subscribe',
    unsubscribe: pushServer + '/pubsub/unsubscribe'
}