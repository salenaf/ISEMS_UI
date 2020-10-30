"use strict";

const models = require("../../../controllers/models");
const mongodbQueryProcessor = require("../../../middleware/mongodbQueryProcessor");

/**
 * Модуль добавляющий новый сущности (организацию, подразделение, источник) в БД
 *
 * @param {*} listValideEntity - объект с новыми сущностями
 */
module.exports = function(listValideEntity) {
    let organizationPromise = (entity) => {
        return new Promise((resolve, reject) => {
            mongodbQueryProcessor.queryCreate(models.modelOrganizationName, {
                document: {
                    id: entity.id_organization,
                    date_register: +(new Date),
                    date_change: +(new Date),
                    name: entity.name,
                    legal_address: entity.legal_address,
                    field_activity: entity.field_activity,
                    division_or_branch_list_id: [],
                }
            }, (err) => {
                if (err) reject(err);
                else resolve();
            });
        });
    };

    let divisionPromise = (entity) => {
        return new Promise((resolve, reject) => {
            mongodbQueryProcessor.querySelect(models.modelOrganizationName, {
                query: { "id": entity.id_organization },
                select: { _id: 0, __v: 0, date_register: 0, data_change: 0, },
            }, (err, info) => {
                if (err) reject(err);
                else resolve(info);
            });
        }).then((info) => {
            if (info === null) {
                return;
            }

            return new Promise((resolve, reject) => {
                //Создаем запись о новом подразделении
                mongodbQueryProcessor.queryCreate(models.modelDivisionBranchName, {
                    document: {
                        id: entity.id_division,
                        id_organization: entity.id_organization,
                        date_register: +(new Date),
                        date_change: +(new Date),
                        name: entity.name,
                        physical_address: entity.physical_address,
                        description: entity.description,
                        source_list: [],
                    }
                }, (err) => {
                    if (err) reject(err);
                    else resolve();
                });
            }).then(() => {
                return new Promise((resolve, reject) => {
                    //Создаем связь между организацией и подразделением
                    mongodbQueryProcessor.queryUpdate(models.modelOrganizationName, {
                        query: {
                            "id": entity.id_organization,
                            "division_or_branch_list_id": { $ne: entity.id_division },
                        },
                        update: { $push: { "division_or_branch_list_id": entity.id_division } },
                    }, (err) => {
                        if (err) reject(err);
                        else resolve();
                    });
                });
            });
        });
    };

    let sourcePromise = (entity) => {
        //Создаем запись о новом источнике
        return new Promise((resolve, reject) => {
            mongodbQueryProcessor.querySelect(models.modelDivisionBranchName, {
                query: { "id": entity.id_division },
                select: { _id: 0, __v: 0, date_register: 0, data_change: 0, },
            }, (err, info) => {
                if (err) reject(err);
                else resolve(info);
            });
        }).then((info) => {
            if (info === null) {
                return;
            }

            return new Promise((resolve, reject) => {
                //Создаем связь между организацией и подразделением
                mongodbQueryProcessor.queryUpdate(models.modelDivisionBranchName, {
                    query: {
                        "id": entity.id_division,
                        "source_list": { $ne: entity.id_source },
                    },
                    update: { $push: { "source_list": entity.id_source } },
                }, (err) => {
                    if (err) reject(err);
                    else resolve();
                });
            }).then(() => {
                return new Promise((resolve, reject) => {
                    mongodbQueryProcessor.queryCreate(models.modelSourcesParameter, {
                        document: {
                            id: entity.id_source,
                            id_division: entity.id_division,
                            source_id: entity.source_id,
                            date_register: +(new Date),
                            date_change: +(new Date),
                            short_name: entity.short_name,
                            network_settings: {
                                ipaddress: entity.network_settings.ipaddress,
                                port: entity.network_settings.port,
                                token_id: entity.network_settings.token_id,
                            },
                            source_settings: {
                                type_architecture_client_server: entity.source_settings.type_architecture_client_server,
                                transmission_telemetry: (entity.source_settings.transmission_telemetry === "on") ? true : false,
                                maximum_number_simultaneous_filtering_processes: +entity.source_settings.maximum_number_simultaneous_filtering_processes,
                                type_channel_layer_protocol: entity.source_settings.type_channel_layer_protocol,
                                list_directories_with_file_network_traffic: entity.source_settings.list_directories_with_file_network_traffic,
                            },
                            description: entity.description,
                            information_about_app: {
                                version: "не определена",
                                date: "не определено",
                            },
                        }
                    }, (err) => {
                        if (err) reject(err);
                        else resolve();
                    });
                });
            });
        });
    };

    let promises = Promise.resolve();
    listValideEntity.forEach((item) => {
        promises = promises.then(() => {
            let organizationID = item.id_organization;
            let divisionID = item.id_division;
            if (organizationID && !divisionID) {
                return organizationPromise(item);
            } else if (organizationID && divisionID) {
                return divisionPromise(item);
            } else {
                return sourcePromise(item);
            }
        });
    });

    return promises;
};