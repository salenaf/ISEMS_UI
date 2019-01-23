/*
 * Подключение страниц приложения
 *
 * Верися 0.1, дата релиза 17.01.2019
 * */


//странита аутентификации
exports.authenticate = require('./authenticate');

//главная страница
exports.mainPage = require('./mainPage');

//анализ пакетов информационной безопасности
exports.analysisSIP = require('./analysisSip');

//управление событиями информационной безопасности
exports.securityEventManagement = require('./securityEventManagement');

//сетевые взаимодействия
exports.networkInteraction = require('./networkInteraction');

/**
 * набор инструментов
 * - инструменты поиска
 * - инструменты декодирования
 */

exports.toolsDecode = require('./tools/toolsDecode');
exports.toolsSearch = require('./tools/toolsSearch');

/**  
 * управление настройками приложения
 * - группами
 * - пользователями
 * - источниками
 * - правилами СОА
 * - правилами поиска
 * - GeoIP
 * - репутационными списками
 * - событими
 */
exports.managementGroups = require('./management/managementGroups');
exports.managementUsers = require('./management/managementUsers');
exports.managementObjectsAndSubjects = require('./management/managementObjectsAndSubjects');
exports.managementIdsRules = require('./management/managementIdsRules');
exports.managementSearchRules = require('./management/managementSearchRules');
exports.managementGeoIp = require('./management/managementGeoIp');
exports.managementReputationalLists = require('./management/managementReputationalLists');