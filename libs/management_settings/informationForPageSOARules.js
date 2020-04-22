"use strict";

const async = require("async");

const models = require("../../controllers/models");
const mongodbQueryProcessor = require("../../middleware/mongodbQueryProcessor");

module.exports = function(callback) {
    console.log("func 'informationForPageSOARules', START...");

    callback(null, "exit");
};