/**
 * Установка и контроль доступности соединения с API waterfall-worker
 *
 * Версия 0.1, дата релиза 06.07.2017
 */

'use strict';

const debug = require('debug')('websocketClientWorkerAPI');
const https = require('https');
const webSocketClient = require('websocket').client;

const config = require('../configure');
const objGlobals = require('../configure/globalObject');
const writeLogFile = require('../libs/writeLogFile');
const routeSocketIo = require('../routes/routeSocketIo');

module.exports = function(socketIo) {
    reconnect(socketIo, function() {
        setInterval(reconnect.bind(null, socketIo, function() {}), config.get('waterfall-worker-api:timerReconnectWebsocketClient'));
    });
};

function reconnect(socketIo, callback) {
    if (typeof objGlobals.description.waterfallWorkerAPI === 'undefined') {
        createWebsocketConnect(socketIo);
    }
    return callback();
}

function createWebsocketConnect(socketIo) {
    if (typeof objGlobals.description.waterfallWorkerAPI !== 'undefined') return;

    debug('------------------ CONNECTION TO WORKER API ----------------------');

    let websocketTmp = new webSocketClient({
        closeTimeout: 3000,
        tlsOptions: {
            host: config.get('waterfall-worker-api:host'),
            port: config.get('waterfall-worker-api:port'),
            servername: config.get('waterfall-worker-api:host'),
            method: 'GET',
            path: '/',
            rejectUnauthorized: false
        }
    });

    websocketTmp.on('connectFailed', function(err) {

        debug('--- WEBSOCKET WATERFALL-WORKER connection failed ---');

        if (typeof objGlobals.description.waterfallWorkerAPI !== 'undefined') {
            delete objGlobals.description.waterfallWorkerAPI;
        }

        if (err) {
            writeLogFile('error', err.toString());
            routeSocketIo.eventGenerator(socketIo, { name: 'waterfall-worker', type: 'API', info: { action: 'connect error' } });
        }
    });

    websocketTmp.on('connect', function(connection) {

        debug('--- WATERFALL-WORKER the connection is established ---');

        if (typeof objGlobals.description.waterfallWorkerAPI !== 'undefined') {
            connection.drop(1000);
        } else {
            objGlobals.description.waterfallWorkerAPI = connection;

            writeLogFile('info', 'connected to the waterfall-worker API');
            routeSocketIo.eventGenerator(socketIo, { name: 'waterfall-worker', type: 'API', info: { action: 'connect' } });
        }

        connection.on('error', function(err) {

            debug('--- WATERFALL-WORKER connection error ---');

            if (err) writeLogFile('error', err.toString());

            if (typeof objGlobals.description.waterfallWorkerAPI !== 'undefined') {
                delete objGlobals.description.waterfallWorkerAPI;
            }

            routeSocketIo.eventGenerator(socketIo, { name: 'waterfall-worker', type: 'API', info: { action: 'connect error' } });
        });

        connection.on('close', function() {

            debug('--- WATERFALL-WORKER connection close ---');

            if (typeof objGlobals.description.waterfallWorkerAPI !== 'undefined') {
                delete objGlobals.description.waterfallWorkerAPI;
            }

            routeSocketIo.eventGenerator(socketIo, { name: 'waterfall-worker', type: 'API', info: { action: 'disconnect' } });
        });

        connection.on('message', function(message) {
            if (message.type === 'utf8') {
                var stringMessage = getParseStringJSON(message);
                routeSocketIo.eventGenerator(socketIo, { name: 'waterfall-worker', type: 'API', info: { action: 'new message', message: stringMessage } });
            } else if (message.type === 'binary') {
                writeLogFile('error', 'taken from the waterfall-worker API binary data (websocket protocol)');
            } else {
                writeLogFile('error', 'taken incorrect data (websocket protocol)');
            }
        });
    });

    websocketTmp.on('error', function(err) {

        debug('--- WEBSOCKET ERROR WATERFALL-WORKER ---');

        if (typeof objGlobals.description.waterfallWorkerAPI !== 'undefined') {
            delete objGlobals.description.waterfallWorkerAPI;
        }

        writeLogFile('error', err.toString());
        routeSocketIo.eventGenerator(socketIo, { name: 'waterfall-worker', type: 'API', info: { action: 'connect error' } });
    });

    let options = {
        host: config.get('waterfall-worker-api:host'),
        port: config.get('waterfall-worker-api:port'),
        method: 'GET',
        path: '/',
        rejectUnauthorized: false,
        headers: {
            'Content-Type': 'text/plain;charset=utf-8',
            'Accept-Language': 'en',
            'User-Agent': 'Mozilla/5.0 (waterfall-UI)',
            'Token': config.get('waterfall-worker-api:token')
        }
    };

    //предварительный HTTP запрос
    var req = https.request(options, function(res) {
        //проверка ответа HTTP сервера
        if (res.statusCode === 200) {
            //запрос на соединение по протоколу webSocket
            websocketTmp.connect('wss://' + config.get('waterfall-worker-api:host') + ':' + config.get('waterfall-worker-api:port'), 'echo-protocol');
        } else {
            routeSocketIo.eventGenerator(socketIo, { name: 'waterfall-worker', type: 'API', info: { connection: 'connect error' } });
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