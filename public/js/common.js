'use strict';

//вывод информационного сообщения
let showNotify = function(type, message) {
    $.notify({
        message: message
    }, {
        type: type,
        placement: { from: 'top', align: 'right' },
        offset: { x: 0, y: 60 }
    });
};

const io = require('socket.io-client');

global.jQuery = require('jquery');
global.$ = require('jquery');

require('bootstrap');
require('bootstrapNotify');
require('bootstrapToggle');
require('datatablesNetBs');
require('bootstrapTokenfield');
require('bootstrapDatetimepicker');

require('moment');
//require('moment-with-locales');

global.socket = io.connect();
global.ss = require('socket.io-stream');
exports.showNotify = showNotify;

//import 'bootstrap.css';