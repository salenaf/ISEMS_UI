/**
 * Возвращает произвольное число из заданного диапазона
 * 
 * Версия 0.1, дата релиза 29.01.2019
 */

"use strict";

function randomInteger(min, max) {
    var rand = min - 0.5 + Math.random() * (max - min + 1);
    rand = Math.round(rand);
    return rand;
}

export { randomInteger };