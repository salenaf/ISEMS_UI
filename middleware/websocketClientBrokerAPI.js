/**
 * Установка и контроль доступности соединения с API waterfall-broker
 *
 * Версия 0.1, дата релиза 25.04.2017
 */

'use strict';

const https = require('https');
const webSocketClient = require('websocket').client;

const config = require('../configure');
const objGlobals = require('../configure/globalObject');
const writeLogFile = require('../libs/writeLogFile');
const routeSocketIo = require('../routes/routeSocketIo');

module.exports = function(socketIo) {
    reconnect(socketIo, function() {
        setInterval(reconnect.bind(null, socketIo, function() {}), config.get('waterfall-broker-api:timerReconnectWebsocketClient'));
    });
};

function reconnect(socketIo, callback) {
    if (typeof objGlobals.description.waterfallBrokerAPI === 'undefined') {
        createWebsocketConnect(socketIo);
    }
    return callback();
}

function createWebsocketConnect(socketIo) {
    let websocketTmp = new webSocketClient({
        closeTimeout: 1000,
        tlsOptions: {
            host: config.get('waterfall-broker-api:host'),
            port: config.get('waterfall-broker-api:port'),
            servername: config.get('waterfall-broker-api:host'),
            method: 'GET',
            path: '/',
            rejectUnauthorized: false
        }
    });

    websocketTmp.on('connectFailed', function(err) {
        if (err) {
            writeLogFile('error', err.toString());
            routeSocketIo.eventGenerator(socketIo, { name: 'waterfall-broker', type: 'API', info: { action: 'connect error' } });
        }
    });

    websocketTmp.on('connect', function(connection) {
        if (typeof objGlobals.description.waterfallBrokerAPI !== 'undefined') {
            connection.drop(1000);
        } else {
            objGlobals.description.waterfallBrokerAPI = connection;

            writeLogFile('info', 'connected to the waterfall-broker API');
            routeSocketIo.eventGenerator(socketIo, { name: 'waterfall-broker', type: 'API', info: { action: 'connect' } });
        }

        connection.on('error', function(err) {
            if (err) writeLogFile('error', err.toString());

            if (typeof objGlobals.description.waterfallBrokerAPI !== 'undefined') {
                delete objGlobals.description.waterfallBrokerAPI;
            }

            routeSocketIo.eventGenerator(socketIo, { name: 'waterfall-broker', type: 'API', info: { action: 'connect error' } });
        });

        connection.on('close', function() {
            if (typeof objGlobals.description.waterfallBrokerAPI !== 'undefined') {
                delete objGlobals.description.waterfallBrokerAPI;
            }

            routeSocketIo.eventGenerator(socketIo, { name: 'waterfall-broker', type: 'API', info: { action: 'disconnect' } });
        });

        connection.on('message', function(message) {
            if (message.type === 'utf8') {
                var stringMessage = getParseStringJSON(message);
                routeSocketIo.eventGenerator(socketIo, { name: 'waterfall-broker', type: 'API', info: { action: 'new message', message: stringMessage } });
            } else if (message.type === 'binary') {
                writeLogFile('error', 'taken from the waterfall-broker API binary data (websocket protocol)');
            } else {
                writeLogFile('error', 'taken incorrect data (websocket protocol)');
            }
        });
    });

    websocketTmp.on('error', function(err) {
        if (typeof objGlobals.description.waterfallBrokerAPI !== 'undefined') {
            delete objGlobals.description.waterfallBrokerAPI;
        }

        writeLogFile('error', err.toString());
        routeSocketIo.eventGenerator(socketIo, { name: 'waterfall-broker', type: 'API', info: { action: 'connect error' } });
    });

    let options = {
        host: config.get('waterfall-broker-api:host'),
        port: config.get('waterfall-broker-api:port'),
        method: 'GET',
        path: '/',
        rejectUnauthorized: false,
        headers: {
            'Content-Type': 'text/plain;charset=utf-8',
            'Accept-Language': 'en',
            'User-Agent': 'Mozilla/5.0 (waterfall-UI)',
            'Token': config.get('waterfall-broker-api:token')
        }
    };

    //предварительный HTTP запрос
    var req = https.request(options, function(res) {
        //проверка ответа HTTP сервера
        if (res.statusCode === 200) {
            //запрос на соединение по протоколу webSocket
            websocketTmp.connect('wss://' + config.get('waterfall-broker-api:host') + ':' + config.get('waterfall-broker-api:port'), 'echo-protocol');
        } else {
            routeSocketIo.eventGenerator(socketIo, { name: 'waterfall-broker', type: 'API', info: { connection: 'connect error' } });
        }

        res.on('data', function(chunk) {});
        res.on('end', function() {});
    });

    req.on('error', function(err) {
        writeLogFile('error', err.toString());
    });

    req.end();
}

//разбирает JSON строку
function getParseStringJSON(stringJSON) {
    try {
        return JSON.parse(stringJSON.utf8Data);
    } catch (err) {
        writeLogFile('error', err.toString());
        return {};
    }
}