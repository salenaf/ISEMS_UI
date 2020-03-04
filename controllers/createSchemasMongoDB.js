/*
 * Создание схем для БД MongoDB
 *
 * создание учетных данных пользователя admininstrator (при отсутствие таковых)
 *
 * Версия 0.1, дата релиза 05.12.2018
 * */

"use strict";

const debug = require("debug")("createSchemasMongoDB");

const async = require("async");
const crypto = require("crypto");

const createUniqID = require("../libs/helpers/createUniqID");
const hashPassword = require("../libs/hashPassword");

module.exports = function(cb) {

    //подключаем модели данных
    let modelUser = require("./models").modelUser;
    let modelGroup = require("./models").modelGroup;
    let modelIdsRules = require("./models").modelRulesIDS;
    let modelAdditionalInformation = require("./models").modelAdditionalInformation;

    async.parallel([
        //дефолтные значения для пользователя administrator
        callback => {
            createModelUsers(modelUser, err => {
                if (err) callback(err);
                else callback(null);
            });
        },
        //дефолтные значения для группы administrator
        callback => {
            createModelGroups(modelGroup, err => {
                if (err) callback(err);
                else callback(null);
            });
        },
        //создание модели для хранения информации об источниках
        /*callback => {
            createModelSource(modelSource, err => {
                if (err) callback(err);
                else callback(null);
            });
        },*/
        //создание модели для хранения решающих правил СОА
        callback => {
            createModelRulesIDS(modelIdsRules, err => {
                if (err) callback(err);
                else callback(null);
            });
        },
        //создание модели для хранения дополнительной информации
        callback => {
            createModelAdditionalInformation(modelAdditionalInformation, err => {
                if (err) callback(err);
                else callback(null);
            });
        }
    ], err => {
        if (err) {
            debug(err);
            
            cb(err);
        }
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
                    description: "Сетевые взаимодействия"
                },
                /*                element_tools: {
                    id: createUniqID.getMD5("administrator_menu_items_element_tools"),
                    name: "инструменты",
                    search_tools: {
                        id: createUniqID.getMD5("administrator_menu_items_element_tools_search_tools"),
                        status: true,
                        description: "поиск информации"
                    },
                    decode_tools: {
                        id: createUniqID.getMD5("administrator_menu_items_element_tools_decode_tools"),
                        status: true,
                        description: "декодирование"
                    }
                },*/
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
                    /*                    setting_objects_and_subjects: {
                        id: createUniqID.getMD5("administrator_menu_items_element_settings_setting_objects_and_subjects"),
                        status: true,
                        description: "объекты и субъекты"
                    },*/
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
                            import: {
                                id: createUniqID.getMD5("administrator_management_network_interaction_management_tasks_filter_import"),
                                status: true,
                                description: "импорт файлов"
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
                            cancel: {
                                id: createUniqID.getMD5("administrator_management_network_interaction_management_tasks_import_cancel"),
                                status: true,
                                description: "отмена"
                            },
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
            /*management_objects_and_subjects: {
                id: createUniqID.getMD5("administrator_management_objects_and_subjects"),
                name: "объекты и субъекты",
                element_settings: {
                    create: {
                        id: createUniqID.getMD5("administrator_management_objects_and_subjects_create"),
                        status: true,
                        description: "создание"
                    },
                    edit: {
                        id: createUniqID.getMD5("administrator_management_objects_and_subjects_edit"),
                        status: true,
                        description: "редактирование"
                    },
                    delete: {
                        id: createUniqID.getMD5("administrator_management_objects_and_subjects_delete"),
                        status: true,
                        description: "удаление"
                    }
                }
            },*/
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

        /**
         * ТЕСТОВАЯ ГРУППА
        
        new modelGroup({
            group_name: "all_users",
            date_register: +(new Date()),
            menu_items: {
                id: createUniqID.getMD5("all_users_menu_items"),
                name: "пункты меню",
                analysis_sip: {
                    id: createUniqID.getMD5("all_users_menu_items_analysis_sip"),
                    status: true,
                    description: "анализ ИПБ"
                },
                security_event_management: {
                    id: createUniqID.getMD5("all_users_menu_items_security_event_management"),
                    status: true,
                    description: "управление событиями"
                },
                network_interaction: {
                    id: createUniqID.getMD5("all_users_menu_items_network_interaction"),
                    status: true,
                    description: "сетевые взаимодействия"
                },
                element_tools: {
                    id: createUniqID.getMD5("all_users_menu_items_element_tools"),
                    name: "инструменты",
                    search_tools: {
                        id: createUniqID.getMD5("all_users_menu_items_element_tools_search_tools"),
                        status: true,
                        description: "поиск информации"
                    },
                    decode_tools: {
                        id: createUniqID.getMD5("all_users_menu_items_element_tools_decode_tools"),
                        status: true,
                        description: "декодирование"
                    }
                },
                element_settings: {
                    id: createUniqID.getMD5("all_users_menu_items_element_settings"),
                    name: "настройки",
                    setting_groups: {
                        id: createUniqID.getMD5("all_users_menu_items_element_settings_setting_groups"),
                        status: true,
                        description: "группы пользователей"
                    },
                    setting_users: {
                        id: createUniqID.getMD5("all_users_menu_items_element_settings_setting_users"),
                        status: true,
                        description: "пользователи"
                    },
                    setting_objects_and_subjects: {
                        id: createUniqID.getMD5("all_users_menu_items_element_settings_setting_objects_and_subjects"),
                        status: true,
                        description: "объекты и субъекты"
                    },
                    setting_ids_rules: {
                        id: createUniqID.getMD5("all_users_menu_items_element_settings_setting_setting_ids_rules"),
                        status: true,
                        description: "правила СОА"
                    },
                    setting_geoip: {
                        id: createUniqID.getMD5("all_users_menu_items_element_settings_setting_setting_geoip"),
                        status: true,
                        description: "геопозиционирование"
                    },
                    setting_reputational_lists: {
                        id: createUniqID.getMD5("all_users_menu_items_element_settings_setting_reputational_lists"),
                        status: true,
                        description: "репутационные списки"
                    },
                    setting_search_rules: {
                        id: createUniqID.getMD5("all_users_menu_items_element_settings_setting_setting_search_rules"),
                        status: true,
                        description: "правила поиска"
                    }
                }
            },
            management_analysis_sip: {
                id: createUniqID.getMD5("all_users_management_analysis_sip"),
                name: "анализ ИПБ",
                element_settings: {
                    save: {
                        id: createUniqID.getMD5("all_users_management_analysis_sip_save"),
                        status: true,
                        description: "сохранение шаблонов"
                    }
                }
            },
            management_security_event_management: {
                id: createUniqID.getMD5("all_users_management_security_event_management"),
                name: "управление событиями",
                element_settings: {
                    create: {
                        id: createUniqID.getMD5("all_users_management_security_event_management_create"),
                        status: false,
                        description: "создание"
                    },
                    editingInformation: {
                        id: createUniqID.getMD5("all_users_management_security_event_management_editingInformation"),
                        status: true,
                        description: "редактирование информации"
                    },
                    statusChange: {
                        id: createUniqID.getMD5("all_users_management_security_event_management_statusChange"),
                        status: false,
                        description: "изменение статуса события"
                    },
                    close: {
                        id: createUniqID.getMD5("all_users_management_security_event_management_sip_close"),
                        status: true,
                        description: "закрытие события"
                    },
                    delete: {
                        id: createUniqID.getMD5("all_users_management_security_event_management_sip_delete"),
                        status: false,
                        description: "удаление события"
                    }
                }
            },
            management_network_interaction: {
                id: createUniqID.getMD5("all_users_management_network_interaction"),
                name: "сетевые взаимодействия",
                element_settings: {
                    management_tasks_filter: {
                        id: createUniqID.getMD5("all_users_management_network_interaction_management_tasks_filter"),
                        name: "фильтрация файлов",
                        element_settings: {
                            create: {
                                id: createUniqID.getMD5("all_users_management_network_interaction_management_tasks_filter_create"),
                                status: true,
                                description: "создание шаблонов"
                            },
                            stop: {
                                id: createUniqID.getMD5("all_users_management_network_interaction_management_tasks_filter_stop"),
                                status: true,
                                description: "останов"
                            },
                            import: {
                                id: createUniqID.getMD5("all_users_management_network_interaction_management_tasks_filter_import"),
                                status: false,
                                description: "импорт файлов"
                            },
                            delete: {
                                id: createUniqID.getMD5("all_users_management_network_interaction_management_tasks_filter_delete"),
                                status: true,
                                description: "удаление"
                            }
                        }
                    },
                    management_tasks_import: {
                        id: createUniqID.getMD5("all_users_management_network_interaction_management_tasks_import"),
                        name: "импорт файлов",
                        element_settings: {
                            cancel: {
                                id: createUniqID.getMD5("all_users_management_network_interaction_management_tasks_import_cancel"),
                                status: true,
                                description: "отмена"
                            },
                            stop: {
                                id: createUniqID.getMD5("all_users_management_network_interaction_management_tasks_import_stop"),
                                status: false,
                                description: "остановка"
                            },
                            resume: {
                                id: createUniqID.getMD5("all_users_management_network_interaction_management_tasks_import_resume"),
                                status: false,
                                description: "возобновление"
                            }
                        }
                    },
                    management_uploaded_files: {
                        id: createUniqID.getMD5("all_users_management_network_interaction_management_uploaded_files"),
                        name: "информация о загруженных файлах",
                        element_settings: {
                            status_change: {
                                id: createUniqID.getMD5("all_users_management_network_interaction_management_uploaded_files_status_change"),
                                status: true,
                                description: "изменение статуса"
                            },
                            delete: {
                                id: createUniqID.getMD5("all_users_management_network_interaction_management_uploaded_files_delete"),
                                status: true,
                                description: "удаление"
                            }
                        }
                    },
                }
            },
            management_users: {
                id: createUniqID.getMD5("all_users_management_users"),
                name: "пользователи",
                element_settings: {
                    create: {
                        id: createUniqID.getMD5("all_users_management_users_create"),
                        status: false,
                        description: "создание"
                    },
                    edit: {
                        id: createUniqID.getMD5("all_users_management_users_edit"),
                        status: false,
                        description: "редактирование"
                    },
                    delete: {
                        id: createUniqID.getMD5("all_users_management_users_delete"),
                        status: true,
                        description: "удаление"
                    }
                }
            },
            management_groups: {
                id: createUniqID.getMD5("all_users_management_groups"),
                name: "группы",
                element_settings: {
                    create: {
                        id: createUniqID.getMD5("all_users_management_groups_create"),
                        status: true,
                        description: "создание"
                    },
                    edit: {
                        id: createUniqID.getMD5("all_users_management_groups_edit"),
                        status: false,
                        description: "редактирование"
                    },
                    delete: {
                        id: createUniqID.getMD5("all_users_management_groups_delete"),
                        status: true,
                        description: "удаление"
                    }
                }
            },
            management_objects_and_subjects: {
                id: createUniqID.getMD5("all_users_management_objects_and_subjects"),
                name: "объекты и субъекты",
                element_settings: {
                    create: {
                        id: createUniqID.getMD5("all_users_management_objects_and_subjects_create"),
                        status: true,
                        description: "создание"
                    },
                    edit: {
                        id: createUniqID.getMD5("all_users_management_objects_and_subjects_edit"),
                        status: true,
                        description: "редактирование"
                    },
                    delete: {
                        id: createUniqID.getMD5("all_users_management_objects_and_subjects_delete"),
                        status: false,
                        description: "удаление"
                    }
                }
            },
            management_ids_rules: {
                id: createUniqID.getMD5("all_users_management_ids_rules"),
                name: "правила СОА",
                element_settings: {
                    create: {
                        id: createUniqID.getMD5("all_users_management_ids_rules_create"),
                        status: false,
                        description: "создание"
                    },
                    delete: {
                        id: createUniqID.getMD5("all_users_management_ids_rules_delete"),
                        status: true,
                        description: "удаление"
                    }
                }
            },
            management_geoip: {
                id: createUniqID.getMD5("all_users_management_geoip"),
                name: "геопозиционирование",
                element_settings: {
                    create: {
                        id: createUniqID.getMD5("all_users_management_geoip_create"),
                        status: true,
                        description: "создание"
                    },
                    delete: {
                        id: createUniqID.getMD5("all_users_management_geoip_delete"),
                        status: true,
                        description: "удаление"
                    }
                }
            },
            management_reputational_lists: {
                id: createUniqID.getMD5("all_users_management_reputational_lists"),
                name: "репутационные списки",
                element_settings: {
                    create: {
                        id: createUniqID.getMD5("all_users_management_reputational_lists_create"),
                        status: true,
                        description: "создание"
                    },
                    edit: {
                        id: createUniqID.getMD5("all_users_management_reputational_lists_edit"),
                        status: false,
                        description: "редактирование"
                    },
                    delete: {
                        id: createUniqID.getMD5("all_users_management_reputational_lists_delete"),
                        status: true,
                        description: "удаление"
                    }
                }
            },
            management_search_rules: {
                id: createUniqID.getMD5("all_users_management_search_rules"),
                name: "правила поиска",
                element_settings: {
                    create: {
                        id: createUniqID.getMD5("all_users_management_search_rules_create"),
                        status: true,
                        description: "создание"
                    },
                    edit: {
                        id: createUniqID.getMD5("all_users_management_search_rules_edit"),
                        status: true,
                        description: "редактирование"
                    },
                    delete: {
                        id: createUniqID.getMD5("all_users_management_search_rules_delete"),
                        status: true,
                        description: "удаление"
                    }
                }
            }
        }).save();

        /**
         * ТЕСТОВАЯ ГРУППА
        
        new modelGroup({
            group_name: "deg_group",
            date_register: +(new Date()),
            menu_items: {
                id: createUniqID.getMD5("deg_group_menu_items"),
                name: "пункты меню",
                analysis_sip: {
                    id: createUniqID.getMD5("deg_group_menu_items_analysis_sip"),
                    status: true,
                    description: "анализ ИПБ"
                },
                security_event_management: {
                    id: createUniqID.getMD5("deg_group_menu_items_security_event_management"),
                    status: true,
                    description: "управление событиями"
                },
                network_interaction: {
                    id: createUniqID.getMD5("deg_group_menu_items_network_interaction"),
                    status: true,
                    description: "сетевые взаимодействия"
                },
                element_tools: {
                    id: createUniqID.getMD5("deg_group_menu_items_element_tools"),
                    name: "инструменты",
                    search_tools: {
                        id: createUniqID.getMD5("deg_group_menu_items_element_tools_search_tools"),
                        status: true,
                        description: "поиск информации"
                    },
                    decode_tools: {
                        id: createUniqID.getMD5("deg_group_menu_items_element_tools_decode_tools"),
                        status: true,
                        description: "декодирование"
                    }
                },
                element_settings: {
                    id: createUniqID.getMD5("deg_group_menu_items_element_settings"),
                    name: "настройки",
                    setting_groups: {
                        id: createUniqID.getMD5("deg_group_menu_items_element_settings_setting_groups"),
                        status: true,
                        description: "группы пользователей"
                    },
                    setting_users: {
                        id: createUniqID.getMD5("deg_group_menu_items_element_settings_setting_users"),
                        status: true,
                        description: "пользователи"
                    },
                    setting_objects_and_subjects: {
                        id: createUniqID.getMD5("deg_group_menu_items_element_settings_setting_objects_and_subjects"),
                        status: true,
                        description: "объекты и субъекты"
                    },
                    setting_ids_rules: {
                        id: createUniqID.getMD5("deg_group_menu_items_element_settings_setting_setting_ids_rules"),
                        status: true,
                        description: "правила СОА"
                    },
                    setting_geoip: {
                        id: createUniqID.getMD5("deg_group_menu_items_element_settings_setting_setting_geoip"),
                        status: true,
                        description: "геопозиционирование"
                    },
                    setting_reputational_lists: {
                        id: createUniqID.getMD5("deg_group_menu_items_element_settings_setting_reputational_lists"),
                        status: true,
                        description: "репутационные списки"
                    },
                    setting_search_rules: {
                        id: createUniqID.getMD5("deg_group_menu_items_element_settings_setting_setting_search_rules"),
                        status: true,
                        description: "правила поиска"
                    }
                }
            },
            management_analysis_sip: {
                id: createUniqID.getMD5("deg_group_management_analysis_sip"),
                name: "анализ ИПБ",
                element_settings: {
                    save: {
                        id: createUniqID.getMD5("deg_group_management_analysis_sip_save"),
                        status: true,
                        description: "сохранение типового шаблона"
                    }
                }
            },
            management_security_event_management: {
                id: createUniqID.getMD5("deg_group_management_security_event_management"),
                name: "управление событиями",
                element_settings: {
                    create: {
                        id: createUniqID.getMD5("deg_group_management_security_event_management_sip_create"),
                        status: true,
                        description: "создание"
                    },
                    editingInformation: {
                        id: createUniqID.getMD5("deg_group_management_security_event_management_editingInformation"),
                        status: true,
                        description: "редактирование информации"
                    },
                    statusChange: {
                        id: createUniqID.getMD5("deg_group_management_security_event_management_statusChange"),
                        status: true,
                        description: "изменение статуса события"
                    },
                    close: {
                        id: createUniqID.getMD5("deg_group_management_security_event_management_close"),
                        status: true,
                        description: "закрытие события"
                    },
                    delete: {
                        id: createUniqID.getMD5("deg_group_management_security_event_management_delete"),
                        status: true,
                        description: "удаление события"
                    }
                }
            },
            management_network_interaction: {
                id: createUniqID.getMD5("deg_group_management_network_interaction"),
                name: "сетевые взаимодействия",
                element_settings: {
                    management_tasks_filter: {
                        id: createUniqID.getMD5("deg_group_management_network_interaction_management_tasks_filter"),
                        name: "фильтрация файлов",
                        element_settings: {
                            create: {
                                id: createUniqID.getMD5("deg_group_management_network_interaction_management_tasks_filter_create"),
                                status: true,
                                description: "создание типового шаблона"
                            },
                            stop: {
                                id: createUniqID.getMD5("deg_group_management_network_interaction_management_tasks_filter_stop"),
                                status: true,
                                description: "останов фильтрации"
                            },
                            import: {
                                id: createUniqID.getMD5("deg_group_management_network_interaction_management_tasks_filter_import"),
                                status: true,
                                description: "импорт файлов"
                            },
                            delete: {
                                id: createUniqID.getMD5("deg_group_management_network_interaction_management_tasks_filter_delete"),
                                status: true,
                                description: "удаление"
                            }
                        }
                    },
                    management_tasks_import: {
                        id: createUniqID.getMD5("deg_group_management_network_interaction_management_tasks_import"),
                        name: "импорт файлов",
                        element_settings: {
                            cancel: {
                                id: createUniqID.getMD5("deg_group_management_network_interaction_management_tasks_import_cancel"),
                                status: true,
                                description: "отмена"
                            },
                            stop: {
                                id: createUniqID.getMD5("deg_group_management_network_interaction_management_tasks_import_stop"),
                                status: true,
                                description: "остановка"
                            },
                            resume: {
                                id: createUniqID.getMD5("deg_group_management_network_interaction_management_tasks_import_resume"),
                                status: true,
                                description: "возобновление"
                            }
                        }
                    },
                    management_uploaded_files: {
                        id: createUniqID.getMD5("deg_group_management_network_interaction_management_uploaded_files"),
                        name: "информация о загруженных файлах",
                        element_settings: {
                            status_change: {
                                id: createUniqID.getMD5("deg_group_management_network_interaction_management_uploaded_files_status_change"),
                                status: true,
                                description: "изменение статуса"
                            },
                            delete: {
                                id: createUniqID.getMD5("deg_group_management_network_interaction_management_uploaded_files_delete"),
                                status: false,
                                description: "удаление"
                            }
                        }
                    },
                }
            },
            management_users: {
                id: createUniqID.getMD5("deg_group_management_users"),
                name: "пользователи",
                element_settings: {
                    create: {
                        id: createUniqID.getMD5("deg_group_management_users_create"),
                        status: false,
                        description: "создание"
                    },
                    edit: {
                        id: createUniqID.getMD5("deg_group_management_users_edit"),
                        status: false,
                        description: "редактирование"
                    },
                    delete: {
                        id: createUniqID.getMD5("deg_group_management_users_delete"),
                        status: true,
                        description: "удаление"
                    }
                }
            },
            management_groups: {
                id: createUniqID.getMD5("deg_group_management_groups"),
                name: "группы",
                element_settings: {
                    create: {
                        id: createUniqID.getMD5("deg_group_management_groups_create"),
                        status: true,
                        description: "создание"
                    },
                    edit: {
                        id: createUniqID.getMD5("deg_group_management_groups_edit"),
                        status: true,
                        description: "редактирование"
                    },
                    delete: {
                        id: createUniqID.getMD5("deg_group_management_groups_delete"),
                        status: true,
                        description: "удаление"
                    }
                }
            },
            management_objects_and_subjects: {
                id: createUniqID.getMD5("deg_group_management_objects_and_subjects"),
                name: "объекты и субъекты",
                element_settings: {
                    create: {
                        id: createUniqID.getMD5("deg_group_management_objects_and_subjects_create"),
                        status: true,
                        description: "создание"
                    },
                    edit: {
                        id: createUniqID.getMD5("deg_group_management_objects_and_subjects_edit"),
                        status: true,
                        description: "редактирование"
                    },
                    delete: {
                        id: createUniqID.getMD5("deg_group_management_objects_and_subjects_delete"),
                        status: false,
                        description: "удаление"
                    }
                }
            },
            management_ids_rules: {
                id: createUniqID.getMD5("deg_group_management_ids_rules"),
                name: "правила СОА",
                element_settings: {
                    create: {
                        id: createUniqID.getMD5("deg_group_management_ids_rules_create"),
                        status: false,
                        description: "создание"
                    },
                    delete: {
                        id: createUniqID.getMD5("deg_group_management_ids_rules_delete"),
                        status: true,
                        description: "удаление"
                    }
                }
            },
            management_geoip: {
                id: createUniqID.getMD5("deg_group_management_geoip"),
                name: "геопозиционирование",
                element_settings: {
                    create: {
                        id: createUniqID.getMD5("deg_group_management_geoip_create"),
                        status: true,
                        description: "создание"
                    },
                    delete: {
                        id: createUniqID.getMD5("deg_group_management_geoip_delete"),
                        status: true,
                        description: "удаление"
                    }
                }
            },
            management_reputational_lists: {
                id: createUniqID.getMD5("deg_group_management_reputational_lists"),
                name: "репутационные списки",
                element_settings: {
                    create: {
                        id: createUniqID.getMD5("deg_group_management_reputational_lists_create"),
                        status: true,
                        description: "создание"
                    },
                    edit: {
                        id: createUniqID.getMD5("deg_group_management_reputational_lists_edit"),
                        status: true,
                        description: "редактирование"
                    },
                    delete: {
                        id: createUniqID.getMD5("deg_group_management_reputational_lists_delete"),
                        status: true,
                        description: "удаление"
                    }
                }
            },
            management_search_rules: {
                id: createUniqID.getMD5("deg_group_management_search_rules"),
                name: "правила поиска",
                element_settings: {
                    create: {
                        id: createUniqID.getMD5("deg_group_management_search_rules_create"),
                        status: true,
                        description: "создание"
                    },
                    edit: {
                        id: createUniqID.getMD5("deg_group_management_search_rules_edit"),
                        status: true,
                        description: "редактирование"
                    },
                    delete: {
                        id: createUniqID.getMD5("deg_group_management_search_rules_delete"),
                        status: true,
                        description: "удаление"
                    }
                }
            }
        }).save();
        */

        next(null);
    });
}

//создание модели хранения данных об источнике
function createModelSource(modelSource, next) {

    debug("find source model");

    modelSource.find(err => {
        if (err) next(err);
        else next(null);
    });
}

//создание модели хранения правил СОА
function createModelRulesIDS(modelIdsRules, next) {

    debug("find IDS rules model");

    modelIdsRules.find({}, { _id: 1 }, err => {
        if (err) next(err);
        else next(null);
    }).limit(1);
}

//создание модели хранения дополнительной информации
function createModelAdditionalInformation(modelAdditionalInformation, next) {

    debug("find model additional informetion");

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