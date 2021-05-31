"use strict";

const ss = require("socket.io-stream");

/** 
 * Маршруты для обработки информации передаваемой через протокол socket.io
 * Обработчик событий поступающих от User Interface
 * 
 * @param {*} eventEmiterTimerTick
 * @param {*} socketIo 
 **/
module.exports.eventHandlingUserInterface = function(eventEmiterTimerTick, socketIo) {
    /* --- УПРАВЛЕНИЕ ПАРОЛЯМИ ПО УМОЛЧАНИЮ --- */
    require("./route_handlers_socketio/handlerChangePassword")(socketIo);

    /* --- УПРАВЛЕНИЕ ПОЛЬЗОВАТЕЛЯМИ --- */
    require("./route_handlers_socketio/handlerActionsUsers").addHandlers(socketIo);

    /* --- УПРАВЛЕНИЕ ГРУППАМИ --- */
    require("./route_handlers_socketio/handlerActionsGroups").addHandlers(socketIo);

    /* --- УПРАВЛЕНИЕ ОРГАНИЗАЦИЯМИ, ПОДРАЗДЕЛЕНИЯМИ И ИСТОЧНИКАМИ --- */
    require("./route_handlers_socketio/handlerActionsOrganizationsAndSources").addHandlers(socketIo);

    /* --- УПРАВЛЕНИЕ ПРАВИЛАМИ СОА --- Поиски указанного SID в БД sid_bd: find-sid */
    require("./route_handlers_socketio/handlerActionRulesSOA").addHandlers(socketIo);

    /* --- УПРАВЛЕНИЕ ОБНОВЛЕНИЕМ ВЫБРАННОГО ПРАВИЛА SID --- */
    require("./route_handlers_socketio/handlerActionUpDateSid").addHandlers(socketIo);

    /* --- УПРАВЛЕНИЕ УДАЛЕНИЕМ ВЫБРАННОГО ПРАВИЛА SID ---*/
    require("./route_handlers_socketio/handlerActionDeleteSid").addHandlers(socketIo);

    /* --- УПРАВЛЕНИЕ ЗАГРУЗКОЙ ИЗ ФАЙЛОВ ПРАВИЛ SID  --- */
    require("./route_handlers_socketio/handlerActionUploadFiles").addHandlers(ss, socketIo);

    /* --- УПРАВЛЕНИЕ ЗАДАЧАМИ ПО ФИЛЬТРАЦИИ ФАЙЛОВ --- */
    require("./route_handlers_socketio/handlerActionsFiltrationTask").addHandlers(socketIo);

    /* --- ПОЛУЧИТЬ ИНФОРМАЦИЮ О ЗАДАЧАХ ВЫПОЛНЯЕМЫХ МОДУЛЕМ СЕТЕВОГО ВЗАИМОДЕЙСТВИЯ --- */
    require("./route_handlers_socketio/networkInteractionHandlerRequestShowTaskInfo").addHandlers(socketIo);

    /* --- ОБРАБОТЧИК ДЕЙСТВИЙ ПРИ СКАЧИВАНИИ ФАЙЛОВ,В ТОМ ЧИСЛЕ ЗАПРОС СПИСКА ЗАДАЧ (пагинатор) --- */
    require("./route_handlers_socketio/handlerActionsDownloadingTasks").addHandlers(socketIo);

    /* --- ОБРАБОТЧИК ДЕЙСТВИЙ СВЯЗАННЫХ С ЗАПРОСАМИ ТЕЛЕМЕТРИИ ИСТОЧНИКОВ --- */
    require("./route_handlers_socketio/networkInteractionHandlerTelemetry").addHandlers(socketIo);

    /* --- ПОЛУЧИТЬ ИНФОРМАЦИЮ ИЗ ЖУРНАЛА ИНФОРМАЦИОННЫХ СООБЩЕНИЙ --- */
    require("./route_handlers_socketio/networkInteractionHandlerNotificationLog").addHandlers(socketIo);

    /* --- ОБРАБОТЧИК ДЕЙСТВИЙ СВЯЗАННЫХ С УПРАВЛЕНИЕМ ШАБЛОНАМИ ВЫПОЛНЯЕМЫХ ЗАДАЧ --- */
    require("./route_handlers_socketio/networkInteractionHandlerTemplate").addHandlers(socketIo, eventEmiterTimerTick);
};