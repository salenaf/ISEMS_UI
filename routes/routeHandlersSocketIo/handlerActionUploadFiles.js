"use strict";

const fs = require("fs");
const path = require("path");

/**
 * Модуль обработчик файлов поступающих из User Interface
 * 
 * @param {*} socketIo 
 */
module.exports.addHandlers = function(ss, socketIo) {
    const handlers = {
        "uploading files with SOA rules": receivedFilesRulesSOA,
    };

    for (let e in handlers) {
        ss(socketIo).on(e, handlers[e].bind(null));
    }
};

function receivedFilesRulesSOA(stream, data){
    console.log("func 'receivedFilesRulesSOA', START...");
    console.log(data);

    console.log(__dirname);
    console.log(__dirname.substr(0, (__dirname.length - 28)));

    let filename = (__dirname.substr(0, (__dirname.length - 28)) + "uploads/") + path.basename(data.name);
    let tempFile = fs.createWriteStream(filename, { flags: "w", defaultEncoding: "utf8", autoClose: true });

    stream.pipe(tempFile);

    tempFile.on("close", () => {
        console.log("UPLOADING FILE IS COMPLETE");
    });

}