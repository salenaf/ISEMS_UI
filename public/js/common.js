"use strict";

const io = require("socket.io-client");

global.jQuery = require("jquery");
global.$ = require("jquery");

require("bootstrap");
require("bootstrapNotify");
require("bootstrapToggle");
require("datatablesNetBs");
require("bootstrapTokenfield");
require("bootstrapDatetimepicker");

require("moment");
//require('moment-with-locales');

global.socket = io.connect();
global.ss = require("socket.io-stream");

//import 'bootstrap.css';