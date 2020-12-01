"use strict";

const io = require("socket.io-client");

global.jQuery = require("jquery");
global.$ = require("jquery");

require("bootstrap");
require("bootstrapNotify");
require("bootstrapToggle");
require("material-ui-lab");
require("material-ui-core");
require("material-ui-pickers");
require("dateIoFnsUtils");
require("datatablesNetBs");
require("reactCustomizeTokenInput");

require("lodash");
require("moment");
require("select2");

require("react-circle");

require("utf8");
require("quoted-printable");

//require('moment-with-locales');

global.socket = io.connect();
global.ss = require("socket.io-stream");

//import 'bootstrap.css';