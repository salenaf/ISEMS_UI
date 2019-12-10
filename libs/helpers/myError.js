"use strict";

class MyError extends Error {
    constructor(name, msg) {
        super(msg);

        this.name = name;
        this.message = msg;
    }
}

module.exports = MyError;