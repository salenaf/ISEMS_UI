/*
 * Описание модели (session.user.information)
 * хранятся данные о пользователе идентифицируемые по passport._id и sessionID
 *
 * Версия 0.1, дата релиза 10.01.2019
 * */

'use strict';

const globalObject = require('../../configure/globalObject');
const connection = globalObject.getData('descriptionDB', 'MongoDB', 'connection');

let sessionUserInformation = new connection.Schema({
    passport_id: String,
    session_id: { type: String, default: '' },
    login: String,
    user_name: String,
    user_settings: {
        sourceMainPage: Array
    },
    group_name: String,
    group_settings: {
        menu_items: {},
        management_analysis_sip: {},
        management_security_event_management: {},
        management_network_interaction: {},
        management_users: {},
        management_groups: {},
        management_objects_and_subjects: {},
        management_ids_rules: {},
        management_search_rules: {},
        management_geoip: {},
        management_reputational_lists: {}
    },
    isPasswordDefaultAdministrator: { type: Boolean, default: false },
    dateCreate: Number
});

module.exports = connection.model('session.user.information', sessionUserInformation);