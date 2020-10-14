/*
 * Создание схем для БД MongoDB
 *
 * создание учетных данных пользователя admininstrator (при отсутствие таковых)
 *
 * Версия 0.2, дата релиза 21.04.2020
 * */

"use strict";

const debug = require("debug")("createSchemasMongoDB");

const async = require("async");
const crypto = require("crypto");

const createUniqID = require("../libs/helpers/createUniqID");
const hashPassword = require("../libs/hashPassword");

module.exports = function(cb) {
    async.parallel([
        //дефолтные значения для пользователя administrator
        (callback) => {
            createModelUsers(require("./models").modelUser, (err) => {
                if (err) callback(err);
                else callback(null);
            });
        },
        //дефолтные значения для группы administrator
        (callback) => {
            createModelGroups(require("./models").modelGroup, (err) => {
                if (err) callback(err);
                else callback(null);
            });
        },
        //создание модели для хранения дополнительной информации
        (callback) => {
            createModelAdditionalInformation(require("./models").modelAdditionalInformation, (err) => {
                if (err) callback(err);
                else callback(null);
            });
        },
        
        //создание модели для поиска вродь !!!!!!!!!!!
        (callback) => {
            createModelRulesIDS(require("./models").modelSOARules, (err) => {
                if (err) callback(err);
                else callback(null);
            });
        }        
        /*
        //создание модели для хранения информации о пользователе по ID passport
        (callback) => {
            createModelAdditionalPassportInformation(require("./models").modelAdditionalPassportInformation, (err) => {
                if (err) callback(err);
                else callback(null);
            });
        }*/
    ], (err) => {
        if (err) cb(err);
        else cb(null);
    });
};

//создание модели пользователей
function createModelUsers(modelUser, next) {
    let md5string = crypto.createHash("md5")
        .update("administrator")
        .digest("hex");

    let password = hashPassword.getHashPassword(md5string, "isems-ui");

    debug("find schema \"user\"");

    modelUser.find({ login: "administrator" }, (err, userAdministrator) => {
        if (err) return next(err);
        if (userAdministrator.length) return next(null);

        debug("add user \"administrator\"");

        new modelUser({
            user_id: createUniqID.getMD5("user_name_administrator"),
            date_register: +(new Date()),
            date_change: +(new Date()),
            login: "administrator",
            password: password,
            group: "administrator",
            user_name: "Администратор",
            settings: {
                sourceMainPage: []
            }
        }).save();

        next(null);
    });
}

//создание модели групп
function createModelGroups(modelGroup, next) {

    debug("find schema \"group\"");

    modelGroup.find({ group_name: "administrator" }, (err, groupAdministrator) => {
        if (err) return next(err);
        if (groupAdministrator.length) return next(null);

        debug("add group \"administrator\"");

        //группа администратора
        new modelGroup({
            group_name: "administrator",
            date_register: +(new Date()),
            menu_items: {
                id: createUniqID.getMD5("administrator_menu_items"),
                name: "пункты меню",
                analysis_sip: {
                    id: createUniqID.getMD5("administrator_menu_items_analysis_sip"),
                    status: true,
                    description: "аналитика"
                },
                security_event_management: {
                    id: createUniqID.getMD5("administrator_menu_items_security_event_management"),
                    status: true,
                    description: "учёт воздействий"
                },
                network_interaction: {
                    id: createUniqID.getMD5("administrator_menu_items_network_interaction"),
                    status: true,
                    description: "сетевые взаимодействия"
                },
                element_settings: {
                    id: createUniqID.getMD5("administrator_menu_items_element_settings"),
                    name: "Настройки",
                    setting_groups: {
                        id: createUniqID.getMD5("administrator_menu_items_element_settings_setting_groups"),
                        status: true,
                        description: "группы пользователей"
                    },
                    setting_users: {
                        id: createUniqID.getMD5("administrator_menu_items_element_settings_setting_users"),
                        status: true,
                        description: "пользователи"
                    },
                    setting_organizations_and_sources: {
                        id: createUniqID.getMD5("administrator_menu_items_element_settings_setting_organizations_and_sources"),
                        status: true,
                        description: "организации и источники"
                    },
                    setting_ids_rules: {
                        id: createUniqID.getMD5("administrator_menu_items_element_settings_setting_setting_ids_rules"),
                        status: true,
                        description: "правила СОА"
                    },
                    setting_geoip: {
                        id: createUniqID.getMD5("administrator_menu_items_element_settings_setting_setting_geoip"),
                        status: true,
                        description: "геопозиционирование"
                    },
                    setting_reputational_lists: {
                        id: createUniqID.getMD5("administrator_menu_items_element_settings_setting_reputational_lists"),
                        status: true,
                        description: "репутационные списки"
                    },
                    setting_search_rules: {
                        id: createUniqID.getMD5("administrator_menu_items_element_settings_setting_setting_search_rules"),
                        status: true,
                        description: "правила поиска"
                    }
                }
            },
            management_analysis_sip: {
                id: createUniqID.getMD5("administrator_management_analysis_sip"),
                name: "аналитика",
                element_settings: {
                    save: {
                        id: createUniqID.getMD5("administrator_management_analysis_sip_save"),
                        status: true,
                        description: "сохранение шаблонов"
                    }
                }
            },
            management_security_event_management: {
                id: createUniqID.getMD5("administrator_management_security_event_management"),
                name: "учёт воздействий",
                element_settings: {
                    create: {
                        id: createUniqID.getMD5("administrator_management_security_event_management_create"),
                        status: true,
                        description: "создание"
                    },
                    editingInformation: {
                        id: createUniqID.getMD5("administrator_management_security_event_management_editingInformation"),
                        status: true,
                        description: "редактирование информации"
                    },
                    statusChange: {
                        id: createUniqID.getMD5("administrator_management_security_event_management_statusChange"),
                        status: true,
                        description: "изменение статуса события"
                    },
                    close: {
                        id: createUniqID.getMD5("administrator_management_security_event_management_close"),
                        status: true,
                        description: "закрытие события"
                    },
                    delete: {
                        id: createUniqID.getMD5("administrator_management_security_event_management_delete"),
                        status: true,
                        description: "удаление события"
                    }
                }
            },
            management_network_interaction: {
                id: createUniqID.getMD5("administrator_management_network_interaction"),
                name: "сетевые взаимодействия",
                element_settings: {
                    management_tasks_filter: {
                        id: createUniqID.getMD5("administrator_management_network_interaction_management_tasks_filter"),
                        name: "фильтрация файлов",
                        element_settings: {
                            create: {
                                id: createUniqID.getMD5("administrator_management_network_interaction_management_tasks_filter_create"),
                                status: true,
                                description: "создание типового шаблона"
                            },
                            stop: {
                                id: createUniqID.getMD5("administrator_management_network_interaction_management_tasks_filter_stop"),
                                status: true,
                                description: "останов фильтрации"
                            },
                            delete: {
                                id: createUniqID.getMD5("administrator_management_network_interaction_management_tasks_filter_delete"),
                                status: true,
                                description: "удаление"
                            }
                        }
                    },
                    management_tasks_import: {
                        id: createUniqID.getMD5("administrator_management_network_interaction_management_tasks_import"),
                        name: "импорт файлов",
                        element_settings: {
                            stop: {
                                id: createUniqID.getMD5("administrator_management_network_interaction_management_tasks_import_stop"),
                                status: true,
                                description: "останов импорта"
                            },
                            resume: {
                                id: createUniqID.getMD5("administrator_management_network_interaction_management_tasks_import_resume"),
                                status: true,
                                description: "возобновление"
                            }
                        }
                    },
                    management_uploaded_files: {
                        id: createUniqID.getMD5("administrator_management_network_interaction_management_uploaded_files"),
                        name: "информация о загруженных файлах",
                        element_settings: {
                            status_change: {
                                id: createUniqID.getMD5("administrator_management_network_interaction_management_uploaded_files_status_change"),
                                status: true,
                                description: "изменение статуса"
                            },
                            delete: {
                                id: createUniqID.getMD5("administrator_management_network_interaction_management_uploaded_files_delete"),
                                status: true,
                                description: "удаление"
                            }
                        }
                    },
                }
            },
            management_users: {
                id: createUniqID.getMD5("administrator_management_users"),
                name: "пользователи",
                element_settings: {
                    create: {
                        id: createUniqID.getMD5("administrator_management_users_create"),
                        status: true,
                        description: "создание"
                    },
                    edit: {
                        id: createUniqID.getMD5("administrator_management_users_edit"),
                        status: true,
                        description: "редактирование"
                    },
                    delete: {
                        id: createUniqID.getMD5("administrator_management_users_delete"),
                        status: true,
                        description: "удаление"
                    }
                }
            },
            management_groups: {
                id: createUniqID.getMD5("administrator_management_groups"),
                name: "группы",
                element_settings: {
                    create: {
                        id: createUniqID.getMD5("administrator_management_groups_create"),
                        status: true,
                        description: "создание"
                    },
                    edit: {
                        id: createUniqID.getMD5("administrator_management_groups_edit"),
                        status: true,
                        description: "редактирование"
                    },
                    delete: {
                        id: createUniqID.getMD5("administrator_management_groups_delete"),
                        status: true,
                        description: "удаление"
                    }
                }
            },
            management_organizations_and_sources: {
                id: createUniqID.getMD5("administrator_management_organizations_and_source"),
                name: "организации и источники",
                element_settings: {
                    management_organizations: {
                        id: createUniqID.getMD5("administrator_management_organizations_and_source_organization"),
                        name: "управление организациями",
                        element_settings: {
                            create: { 
                                id: createUniqID.getMD5("administrator_management_organizations_and_source_organization_create"), 
                                status: true, 
                                description: "создание" 
                            },
                            edit: { 
                                id: createUniqID.getMD5("administrator_management_organizations_and_source_organization_edit"),  
                                status: true, 
                                description: "редактирование" 
                            },
                            delete: { 
                                id: createUniqID.getMD5("administrator_management_organizations_and_source_organization_delete"), 
                                status: true, 
                                description: "удаление" 
                            }
                        }
                    },
                    management_division: {
                        id: createUniqID.getMD5("administrator_management_organizations_and_source_division"),
                        name: "управление подразделениями",
                        element_settings: {
                            create: { 
                                id: createUniqID.getMD5("administrator_management_organizations_and_source_division_create"), 
                                status: true, 
                                description: "создание" 
                            },
                            edit: { 
                                id: createUniqID.getMD5("administrator_management_organizations_and_source_division_edit"),  
                                status: true, 
                                description: "редактирование" 
                            },
                            delete: { 
                                id: createUniqID.getMD5("administrator_management_organizations_and_source_division_delete"), 
                                status: true, 
                                description: "удаление" 
                            }
                        }
                    },
                    management_sources: {
                        id: createUniqID.getMD5("administrator_management_organizations_and_source_sources"),
                        name: "управление источниками",
                        element_settings: {
                            create: { 
                                id: createUniqID.getMD5("administrator_management_organizations_and_source_sources_create"), 
                                status: true, 
                                description: "создание" 
                            },
                            edit: { 
                                id: createUniqID.getMD5("administrator_management_organizations_and_source_sources_edit"),  
                                status: true, 
                                description: "редактирование" 
                            },
                            delete: { 
                                id: createUniqID.getMD5("administrator_management_organizations_and_source_sources_delete"), 
                                status: true, 
                                description: "удаление" 
                            }
                        }
                    },
                },
            },
            management_ids_rules: {
                id: createUniqID.getMD5("administrator_management_ids_rules"),
                name: "правила СОА",
                element_settings: {
                    create: {
                        id: createUniqID.getMD5("administrator_management_ids_rules_create"),
                        status: true,
                        description: "создание"
                    },
                    delete: {
                        id: createUniqID.getMD5("administrator_management_ids_rules_delete"),
                        status: true,
                        description: "удаление"
                    }
                }
            },
            management_geoip: {
                id: createUniqID.getMD5("administrator_management_geoip"),
                name: "геопозиционирование",
                element_settings: {
                    create: {
                        id: createUniqID.getMD5("administrator_management_geoip_create"),
                        status: true,
                        description: "создание"
                    },
                    delete: {
                        id: createUniqID.getMD5("administrator_management_geoip_delete"),
                        status: true,
                        description: "удаление"
                    }
                }
            },
            management_reputational_lists: {
                id: createUniqID.getMD5("administrator_management_reputational_lists"),
                name: "репутационные списки",
                element_settings: {
                    create: {
                        id: createUniqID.getMD5("administrator_management_reputational_lists_create"),
                        status: true,
                        description: "создание"
                    },
                    edit: {
                        id: createUniqID.getMD5("administrator_management_reputational_lists_edit"),
                        status: true,
                        description: "редактирование"
                    },
                    delete: {
                        id: createUniqID.getMD5("administrator_management_reputational_lists_delete"),
                        status: true,
                        description: "удаление"
                    }
                }
            },
            management_search_rules: {
                id: createUniqID.getMD5("administrator_management_search_rules"),
                name: "правила поиска",
                element_settings: {
                    create: {
                        id: createUniqID.getMD5("administrator_management_search_rules_create"),
                        status: true,
                        description: "создание"
                    },
                    edit: {
                        id: createUniqID.getMD5("administrator_management_search_rules_edit"),
                        status: true,
                        description: "редактирование"
                    },
                    delete: {
                        id: createUniqID.getMD5("administrator_management_search_rules_delete"),
                        status: true,
                        description: "удаление"
                    }
                }
            }
        }).save();

        next(null);
    });
}

/*
function createModelAdditionalPassportInformation(modelAdditionalPassportInformation, next) {

}

//создание модели хранения данных об источнике
function createModelSource(modelSource, next) {

    debug("find source model");

    modelSource.find(err => {
        if (err) next(err);
        else next(null);
    });
}
*/
//создание модели хранения правил СОА
function createModelRulesIDS(modelSOARules, next) {

    debug("find IDS rules model");
    
    modelSOARules.find({}, { _id: 1 }, (err, list) => {
        if (err) {
            next(err);
        } else {
            if(list.length === 0){
                /*  new modelSOARules({
                    sid: 0000,
                    classType: "trojan-activity",
                    msg: "Test Rules",
                    body: "ndiiig ifgfilghfigif h fdh "
                }).save();

                new modelSOARules({
                    sid: 1001,
                    classType: "trojan-activity",
                    msg: "Test Rules 2",
                    body: "ndiiig ifgfilghfigif h fdh "
                }).save();*/
            }

            next(null);
        }
    }).limit(1);
}


//создание модели хранения дополнительной информации
function createModelAdditionalInformation(modelAdditionalInformation, next) {
    modelAdditionalInformation.find({}, { _id: 1 }, (err, document) => {
        if (err) return next(err);
        if (document.length > 0) return next(null);

        new modelAdditionalInformation({
            ids_rules: {
                create_date: +new Date(),
                create_login: "administrator",
                create_username: "Администратор",
                count_rules: 0
            }
        }).save();

        next(null);
    });
}