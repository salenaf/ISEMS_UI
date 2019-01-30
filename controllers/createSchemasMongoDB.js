/*
 * Создание схем для БД MongoDB
 *
 * создание дефолтных учетных данных пользователя admin (при отсутствие таковых)
 *
 * Версия 0.1, дата релиза 05.12.2018
 * */

'use strict';

const debug = require('debug')('createSchemasMongoDB');

const async = require('async');
const crypto = require('crypto');

const hashPassword = require('../libs/hashPassword');

module.exports = function(cb) {

    //подключаем модели данных
    let modelUser = require('./models').modelUser;
    let modelGroup = require('./models').modelGroup;
    let modelSource = require('./models').modelSource;
    let modelIdsRules = require('./models').modelRulesIDS;
    let modelAdditionalInformation = require('./models').modelAdditionalInformation;

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
        callback => {
            createModelSource(modelSource, err => {
                if (err) callback(err);
                else callback(null);
            });
        },
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
        if (err) cb(err);
        else cb(null);
    });
};

//создание модели пользователей
function createModelUsers(modelUser, next) {
    let md5string = crypto.createHash('md5')
        .update('administrator')
        .digest('hex');

    let password = hashPassword.getHashPassword(md5string, 'isems-ui');

    debug('find schema "user"');

    modelUser.find({ login: 'administrator' }, (err, userAdministrator) => {
        if (err) return next(err);
        if (userAdministrator.length) return next(null);

        debug('add user "administrator"');

        new modelUser({
            date_register: +(new Date()),
            date_change: +(new Date()),
            login: 'administrator',
            password: password,
            group: 'administrator',
            user_name: 'Администратор',
            settings: {
                sourceMainPage: []
            }
        }).save();
        next(null);
    });
}

//создание модели групп
function createModelGroups(modelGroup, next) {

    debug('find schema "group"');

    modelGroup.find({ group_name: 'administrator' }, (err, groupAdministrator) => {
        if (err) return next(err);
        if (groupAdministrator.length) return next(null);

        debug('add group "administrator"');

        //группа администратора
        new modelGroup({
            group_name: 'administrator',
            date_register: +(new Date()),
            menu_items: {
                name: 'пункты меню',
                analysis_sip: { status: true, description: 'анализ ИПБ' },
                security_event_management: { status: true, description: 'управление событиями' },
                network_interaction: { status: true, description: 'сетевые взаимодействия' },
                element_tools: {
                    name: 'инструменты',
                    search_tools: { status: true, description: 'поиск информации' },
                    decode_tools: { status: true, description: 'декодирование' }
                },
                element_settings: {
                    name: 'настройки',
                    setting_groups: { status: true, description: 'группы пользователей' },
                    setting_users: { status: true, description: 'пользователи' },
                    setting_objects_and_subjects: { status: true, description: 'объекты и субъекты' },
                    setting_ids_rules: { status: true, description: 'правила СОА' },
                    setting_geoip: { status: true, description: 'геопозиционирование' },
                    setting_reputational_lists: { status: true, description: 'репутационные списки' },
                    setting_search_rules: { status: true, description: 'правила поиска' }
                }
            },
            management_analysis_sip: {
                name: 'анализ ИПБ',
                element_settings: {
                    read: { status: true, description: 'просмотр' }
                }
            },
            management_security_event_management: {
                name: 'управление событиями',
                element_settings: {
                    creat: { status: true, description: 'создание' },
                    editingInformation: { status: true, description: 'редактирование информации' },
                    statusChange: { status: true, description: 'изменение статуса события' },
                    close: { status: true, description: 'закрытие события' },
                    delete: { status: true, description: 'удаление события' }
                }
            },
            management_network_interaction: {
                name: 'сетевые взаимодействия',
                element_settings: {
                    management_tasks_filter: {
                        name: 'фильтрация файлов',
                        element_settings: {
                            read: { status: true, description: 'просмотр' },
                            import: { status: true, description: 'импорт файлов' },
                            delete: { status: true, description: 'удаление' }
                        }
                    },
                    management_tasks_import: {
                        name: 'импорт файлов',
                        element_settings: {
                            cancel: { status: true, description: 'отмена' },
                            stop: { status: true, description: 'остановка' },
                            resume: { status: true, description: 'возобновление' }
                        }
                    },
                    management_uploaded_files: {
                        name: 'информация о загруженных файлах',
                        element_settings: {
                            status_change: { status: true, description: 'изменение статуса' },
                            delete: { status: true, description: 'удаление' }
                        }
                    },
                }
            },
            management_search_tools: {
                name: 'поиск информации',
                element_settings: {
                    read: { status: true, description: 'просмотр' }
                }
            },
            management_decode_tools: {
                name: 'декодирование',
                element_settings: {
                    read: { status: true, description: 'просмотр' }
                }
            },
            management_users: {
                name: 'пользователи',
                element_settings: {
                    create: { status: true, description: 'создание' },
                    read: { status: true, description: 'просмотр' },
                    edit: { status: true, description: 'редактирование' },
                    delete: { status: true, description: 'удаление' }
                }
            },
            management_groups: {
                name: 'группы',
                element_settings: {
                    create: { status: true, description: 'создание' },
                    read: { status: true, description: 'просмотр' },
                    edit: { status: true, description: 'редактирование' },
                    delete: { status: true, description: 'удаление' }
                }
            },
            management_objects_and_subjects: {
                name: 'объекты и субъекты',
                element_settings: {
                    create: { status: true, description: 'создание' },
                    read: { status: true, description: 'просмотр' },
                    edit: { status: true, description: 'редактирование' },
                    delete: { status: true, description: 'удаление' }
                }
            },
            management_ids_rules: {
                name: 'правила СОА',
                element_settings: {
                    create: { status: true, description: 'создание' },
                    read: { status: true, description: 'просмотр' },
                    delete: { status: true, description: 'удаление' }
                }
            },
            management_geoip: {
                name: 'геопозиционирование',
                element_settings: {
                    create: { status: true, description: 'создание' },
                    read: { status: true, description: 'просмотр' },
                    delete: { status: true, description: 'удаление' }
                }
            },
            management_reputational_lists: {
                name: 'репутационные списки',
                element_settings: {
                    create: { status: true, description: 'создание' },
                    read: { status: true, description: 'просмотр' },
                    edit: { status: true, description: 'редактирование' },
                    delete: { status: true, description: 'удаление' }
                }
            },
            management_search_rules: {
                name: 'правила поиска',
                element_settings: {
                    create: { status: true, description: 'создание' },
                    read: { status: true, description: 'просмотр' },
                    edit: { status: true, description: 'редактирование' },
                    delete: { status: true, description: 'удаление' }
                }
            },
            management_events: {
                name: 'события',
                element_settings: {
                    read: { status: true, description: 'просмотр' },
                    delete: { status: true, description: 'удаление' }
                }
            }
        }).save();

        /**
         * ТЕСТОВАЯ ГРУППА
         */
        new modelGroup({
            group_name: 'all_users',
            date_register: +(new Date()),
            menu_items: {
                name: 'пункты меню',
                analysis_sip: { status: false, description: 'анализ ИПБ' },
                security_event_management: { status: true, description: 'управление событиями' },
                network_interaction: { status: true, description: 'сетевые взаимодействия' },
                element_tools: {
                    name: 'инструменты',
                    search_tools: { status: true, description: 'поиск информации' },
                    decode_tools: { status: true, description: 'декодирование' }
                },
                element_settings: {
                    name: 'настройки',
                    setting_groups: { status: true, description: 'группы пользователей' },
                    setting_users: { status: true, description: 'пользователи' },
                    setting_objects_and_subjects: { status: true, description: 'объекты и субъекты' },
                    setting_ids_rules: { status: true, description: 'правила СОА' },
                    setting_geoip: { status: true, description: 'геопозиционирование' },
                    setting_reputational_lists: { status: true, description: 'репутационные списки' },
                    setting_search_rules: { status: true, description: 'правила поиска' }
                }
            },
            management_analysis_sip: {
                name: 'анализ ИПБ',
                element_settings: {
                    read: { status: false, description: 'просмотр' }
                }
            },
            management_security_event_management: {
                name: 'управление событиями',
                element_settings: {
                    creat: { status: false, description: 'создание' },
                    editingInformation: { status: true, description: 'редактирование информации' },
                    statusChange: { status: false, description: 'изменение статуса события' },
                    close: { status: true, description: 'закрытие события' },
                    delete: { status: true, description: 'удаление события' }
                }
            },
            management_network_interaction: {
                name: 'сетевые взаимодействия',
                element_settings: {
                    management_tasks_filter: {
                        name: 'фильтрация файлов',
                        element_settings: {
                            read: { status: true, description: 'просмотр' },
                            import: { status: true, description: 'импорт файлов' },
                            delete: { status: false, description: 'удаление' }
                        }
                    },
                    management_tasks_import: {
                        name: 'импорт файлов',
                        element_settings: {
                            cancel: { status: true, description: 'отмена' },
                            stop: { status: false, description: 'остановка' },
                            resume: { status: true, description: 'возобновление' }
                        }
                    },
                    management_uploaded_files: {
                        name: 'информация о загруженных файлах',
                        element_settings: {
                            status_change: { status: true, description: 'изменение статуса' },
                            delete: { status: true, description: 'удаление' }
                        }
                    },
                }
            },
            management_search_tools: {
                name: 'поиск информации',
                element_settings: {
                    read: { status: true, description: 'просмотр' }
                }
            },
            management_decode_tools: {
                name: 'декодирование',
                element_settings: {
                    read: { status: true, description: 'просмотр' }
                }
            },
            management_users: {
                name: 'пользователи',
                element_settings: {
                    create: { status: true, description: 'создание' },
                    read: { status: true, description: 'просмотр' },
                    edit: { status: true, description: 'редактирование' },
                    delete: { status: true, description: 'удаление' }
                }
            },
            management_groups: {
                name: 'группы',
                element_settings: {
                    create: { status: true, description: 'создание' },
                    read: { status: true, description: 'просмотр' },
                    edit: { status: true, description: 'редактирование' },
                    delete: { status: true, description: 'удаление' }
                }
            },
            management_objects_and_subjects: {
                name: 'объекты и субъекты',
                element_settings: {
                    create: { status: true, description: 'создание' },
                    read: { status: true, description: 'просмотр' },
                    edit: { status: true, description: 'редактирование' },
                    delete: { status: true, description: 'удаление' }
                }
            },
            management_ids_rules: {
                name: 'правила СОА',
                element_settings: {
                    create: { status: true, description: 'создание' },
                    read: { status: true, description: 'просмотр' },
                    delete: { status: true, description: 'удаление' }
                }
            },
            management_geoip: {
                name: 'геопозиционирование',
                element_settings: {
                    create: { status: true, description: 'создание' },
                    read: { status: true, description: 'просмотр' },
                    delete: { status: false, description: 'удаление' }
                }
            },
            management_reputational_lists: {
                name: 'репутационные списки',
                element_settings: {
                    create: { status: true, description: 'создание' },
                    read: { status: true, description: 'просмотр' },
                    edit: { status: true, description: 'редактирование' },
                    delete: { status: false, description: 'удаление' }
                }
            },
            management_search_rules: {
                name: 'правила поиска',
                element_settings: {
                    create: { status: false, description: 'создание' },
                    read: { status: true, description: 'просмотр' },
                    edit: { status: false, description: 'редактирование' },
                    delete: { status: false, description: 'удаление' }
                }
            },
            management_events: {
                name: 'события',
                element_settings: {
                    read: { status: true, description: 'просмотр' },
                    delete: { status: false, description: 'удаление' }
                }
            }
        }).save();

        /**
         * ТЕСТОВАЯ ГРУППА
         */
        new modelGroup({
            group_name: 'deg_group',
            date_register: +(new Date()),
            menu_items: {
                name: 'пункты меню',
                analysis_sip: { status: false, description: 'анализ ИПБ' },
                security_event_management: { status: true, description: 'управление событиями' },
                network_interaction: { status: true, description: 'сетевые взаимодействия' },
                element_tools: {
                    name: 'инструменты',
                    search_tools: { status: true, description: 'поиск информации' },
                    decode_tools: { status: true, description: 'декодирование' }
                },
                element_settings: {
                    name: 'настройки',
                    setting_groups: { status: true, description: 'группы пользователей' },
                    setting_users: { status: true, description: 'пользователи' },
                    setting_objects_and_subjects: { status: true, description: 'объекты и субъекты' },
                    setting_ids_rules: { status: true, description: 'правила СОА' },
                    setting_geoip: { status: true, description: 'геопозиционирование' },
                    setting_reputational_lists: { status: true, description: 'репутационные списки' },
                    setting_search_rules: { status: true, description: 'правила поиска' }
                }
            },
            management_analysis_sip: {
                name: 'анализ ИПБ',
                element_settings: {
                    read: { status: false, description: 'просмотр' }
                }
            },
            management_security_event_management: {
                name: 'управление событиями',
                element_settings: {
                    creat: { status: false, description: 'создание' },
                    editingInformation: { status: true, description: 'редактирование информации' },
                    statusChange: { status: false, description: 'изменение статуса события' },
                    close: { status: true, description: 'закрытие события' },
                    delete: { status: true, description: 'удаление события' }
                }
            },
            management_network_interaction: {
                name: 'сетевые взаимодействия',
                element_settings: {
                    management_tasks_filter: {
                        name: 'фильтрация файлов',
                        element_settings: {
                            read: { status: true, description: 'просмотр' },
                            import: { status: false, description: 'импорт файлов' },
                            delete: { status: true, description: 'удаление' }
                        }
                    },
                    management_tasks_import: {
                        name: 'импорт файлов',
                        element_settings: {
                            cancel: { status: true, description: 'отмена' },
                            stop: { status: false, description: 'остановка' },
                            resume: { status: false, description: 'возобновление' }
                        }
                    },
                    management_uploaded_files: {
                        name: 'информация о загруженных файлах',
                        element_settings: {
                            status_change: { status: true, description: 'изменение статуса' },
                            delete: { status: true, description: 'удаление' }
                        }
                    },
                }
            },
            management_search_tools: {
                name: 'поиск информации',
                element_settings: {
                    read: { status: true, description: 'просмотр' }
                }
            },
            management_decode_tools: {
                name: 'декодирование',
                element_settings: {
                    read: { status: true, description: 'просмотр' }
                }
            },
            management_users: {
                name: 'пользователи',
                element_settings: {
                    create: { status: true, description: 'создание' },
                    read: { status: true, description: 'просмотр' },
                    edit: { status: true, description: 'редактирование' },
                    delete: { status: true, description: 'удаление' }
                }
            },
            management_groups: {
                name: 'группы',
                element_settings: {
                    create: { status: false, description: 'создание' },
                    read: { status: true, description: 'просмотр' },
                    edit: { status: true, description: 'редактирование' },
                    delete: { status: true, description: 'удаление' }
                }
            },
            management_objects_and_subjects: {
                name: 'объекты и субъекты',
                element_settings: {
                    create: { status: true, description: 'создание' },
                    read: { status: true, description: 'просмотр' },
                    edit: { status: true, description: 'редактирование' },
                    delete: { status: true, description: 'удаление' }
                }
            },
            management_ids_rules: {
                name: 'правила СОА',
                element_settings: {
                    create: { status: true, description: 'создание' },
                    read: { status: true, description: 'просмотр' },
                    delete: { status: true, description: 'удаление' }
                }
            },
            management_geoip: {
                name: 'геопозиционирование',
                element_settings: {
                    create: { status: true, description: 'создание' },
                    read: { status: true, description: 'просмотр' },
                    delete: { status: false, description: 'удаление' }
                }
            },
            management_reputational_lists: {
                name: 'репутационные списки',
                element_settings: {
                    create: { status: true, description: 'создание' },
                    read: { status: true, description: 'просмотр' },
                    edit: { status: true, description: 'редактирование' },
                    delete: { status: true, description: 'удаление' }
                }
            },
            management_search_rules: {
                name: 'правила поиска',
                element_settings: {
                    create: { status: true, description: 'создание' },
                    read: { status: true, description: 'просмотр' },
                    edit: { status: true, description: 'редактирование' },
                    delete: { status: true, description: 'удаление' }
                }
            },
            management_events: {
                name: 'события',
                element_settings: {
                    read: { status: true, description: 'просмотр' },
                    delete: { status: false, description: 'удаление' }
                }
            }
        }).save();

        /**
         * ТЕСТОВАЯ ГРУППА
         */
        new modelGroup({
            group_name: 'test_group',
            date_register: +(new Date()),
            menu_items: {
                name: 'пункты меню',
                analysis_sip: { status: false, description: 'анализ ИПБ' },
                security_event_management: { status: true, description: 'управление событиями' },
                network_interaction: { status: true, description: 'сетевые взаимодействия' },
                element_tools: {
                    name: 'инструменты',
                    search_tools: { status: true, description: 'поиск информации' },
                    decode_tools: { status: true, description: 'декодирование' }
                },
                element_settings: {
                    name: 'настройки',
                    setting_groups: { status: true, description: 'группы пользователей' },
                    setting_users: { status: true, description: 'пользователи' },
                    setting_objects_and_subjects: { status: true, description: 'объекты и субъекты' },
                    setting_ids_rules: { status: true, description: 'правила СОА' },
                    setting_geoip: { status: true, description: 'геопозиционирование' },
                    setting_reputational_lists: { status: true, description: 'репутационные списки' },
                    setting_search_rules: { status: true, description: 'правила поиска' }
                }
            },
            management_analysis_sip: {
                name: 'анализ ИПБ',
                element_settings: {
                    read: { status: false, description: 'просмотр' }
                }
            },
            management_security_event_management: {
                name: 'управление событиями',
                element_settings: {
                    creat: { status: false, description: 'создание' },
                    editingInformation: { status: true, description: 'редактирование информации' },
                    statusChange: { status: false, description: 'изменение статуса события' },
                    close: { status: true, description: 'закрытие события' },
                    delete: { status: true, description: 'удаление события' }
                }
            },
            management_network_interaction: {
                name: 'сетевые взаимодействия',
                element_settings: {
                    management_tasks_filter: {
                        name: 'фильтрация файлов',
                        element_settings: {
                            read: { status: true, description: 'просмотр' },
                            import: { status: true, description: 'импорт файлов' },
                            delete: { status: false, description: 'удаление' }
                        }
                    },
                    management_tasks_import: {
                        name: 'импорт файлов',
                        element_settings: {
                            cancel: { status: true, description: 'отмена' },
                            stop: { status: false, description: 'остановка' },
                            resume: { status: true, description: 'возобновление' }
                        }
                    },
                    management_uploaded_files: {
                        name: 'информация о загруженных файлах',
                        element_settings: {
                            status_change: { status: true, description: 'изменение статуса' },
                            delete: { status: true, description: 'удаление' }
                        }
                    },
                }
            },
            management_search_tools: {
                name: 'поиск информации',
                element_settings: {
                    read: { status: true, description: 'просмотр' }
                }
            },
            management_decode_tools: {
                name: 'декодирование',
                element_settings: {
                    read: { status: true, description: 'просмотр' }
                }
            },
            management_users: {
                name: 'пользователи',
                element_settings: {
                    create: { status: true, description: 'создание' },
                    read: { status: true, description: 'просмотр' },
                    edit: { status: true, description: 'редактирование' },
                    delete: { status: true, description: 'удаление' }
                }
            },
            management_groups: {
                name: 'группы',
                element_settings: {
                    create: { status: true, description: 'создание' },
                    read: { status: true, description: 'просмотр' },
                    edit: { status: true, description: 'редактирование' },
                    delete: { status: true, description: 'удаление' }
                }
            },
            management_objects_and_subjects: {
                name: 'объекты и субъекты',
                element_settings: {
                    create: { status: true, description: 'создание' },
                    read: { status: true, description: 'просмотр' },
                    edit: { status: true, description: 'редактирование' },
                    delete: { status: true, description: 'удаление' }
                }
            },
            management_ids_rules: {
                name: 'правила СОА',
                element_settings: {
                    create: { status: true, description: 'создание' },
                    read: { status: true, description: 'просмотр' },
                    delete: { status: true, description: 'удаление' }
                }
            },
            management_geoip: {
                name: 'геопозиционирование',
                element_settings: {
                    create: { status: true, description: 'создание' },
                    read: { status: true, description: 'просмотр' },
                    delete: { status: false, description: 'удаление' }
                }
            },
            management_reputational_lists: {
                name: 'репутационные списки',
                element_settings: {
                    create: { status: true, description: 'создание' },
                    read: { status: true, description: 'просмотр' },
                    edit: { status: true, description: 'редактирование' },
                    delete: { status: true, description: 'удаление' }
                }
            },
            management_search_rules: {
                name: 'правила поиска',
                element_settings: {
                    create: { status: true, description: 'создание' },
                    read: { status: true, description: 'просмотр' },
                    edit: { status: true, description: 'редактирование' },
                    delete: { status: true, description: 'удаление' }
                }
            },
            management_events: {
                name: 'события',
                element_settings: {
                    read: { status: true, description: 'просмотр' },
                    delete: { status: false, description: 'удаление' }
                }
            }
        }).save();

        next(null);
    });
}

//создание модели хранения данных об источнике
function createModelSource(modelSource, next) {

    debug('find source model');

    modelSource.find(err => {
        if (err) next(err);
        else next(null);
    });
}

//создание модели хранения правил СОА
function createModelRulesIDS(modelIdsRules, next) {

    debug('find IDS rules model');

    modelIdsRules.find({}, { _id: 1 }, err => {
        if (err) next(err);
        else next(null);
    }).limit(1);
}

//создание модели хранения дополнительной информации
function createModelAdditionalInformation(modelAdditionalInformation, next) {

    debug('find model additional informetion');

    modelAdditionalInformation.find({}, { _id: 1 }, (err, document) => {
        if (err) return next(err);
        if (document.length > 0) return next(null);

        new modelAdditionalInformation({
            ids_rules: {
                create_date: +new Date(),
                create_login: 'administrator',
                create_username: 'Администратор',
                count_rules: 0
            }
        }).save();
        next(null);
    });
}