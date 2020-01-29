"use strict";

const helpers = {
//генератор токена
    tokenRand() {
        return (Math.random().toString(14).substr(2)) + (Math.random().toString(14).substr(2));
    }
};

export { helpers };