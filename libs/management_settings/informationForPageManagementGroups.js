/*
 * Подготовка информации для вывода на странице settings_groups
 *
 * Версия 0.1, дата релиза 03.04.2017
 * */

'use strict';

const models = require('../../controllers/models');
const mongodbQueryProcessor = require('../../middleware/mongodbQueryProcessor');

module.exports = function(cb) {
    let arrayNameItems = [
        'menu_items',
        'management_analysis_sip',
        'management_event_management',
        'management_network_interaction',
        'management_search_tools',
        'management_decode_tools',
        'management_users',
        'management_groups',
        'management_objects_and_subjects',
        'management_ids_rules',
        'management_geoip',
        'management_search_rules',
        'management_reputational_lists',
        'management_events'
    ];

    mongodbQueryProcessor.querySelect(models.modelGroup, { isMany: true }, (err, groups) => {
        if (err) return cb(err);

        let objGroup = {};
        for (let i = 0; i < groups.length; i++) {
            objGroup[groups[i].group_name] = {};
            objGroup[groups[i].group_name].dateRegister = groups[i].date_register;
            objGroup[groups[i].group_name].elements = {};

            arrayNameItems.forEach(item => {
                objGroup[groups[i].group_name].elements[item] = {};
                Object.assign(objGroup[groups[i].group_name].elements[item], groups[i][item]);
            });
        }

        cb(null, objGroup);
    });
};