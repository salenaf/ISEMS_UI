/*
 * Описание модели группы пользователей
 *
 * Версия 0.1, дата релиза 21.01.2019
 * */

'use strict';

const globalObject = require('../../configure/globalObject');
const connection = globalObject.getData('descriptionDB', 'MongoDB', 'connection');

let groupSchema = new connection.Schema({
    group_name: String,
    date_register: Number,
    menu_items: {
        name: String,
        analysis_sip: { status: Boolean, description: String },
        security_event_management: { status: Boolean, description: String },
        network_interaction: { status: Boolean, description: String },
        element_tools: {
            name: String,
            search_tools: { status: Boolean, description: String },
            decode_tools: { status: Boolean, description: String }
        },
        element_settings: {
            name: String,
            setting_groups: { status: Boolean, description: String },
            setting_users: { status: Boolean, description: String },
            setting_objects_and_subjects: { status: Boolean, description: String },
            setting_ids_rules: { status: Boolean, description: String },
            setting_geoip: { status: Boolean, description: String },
            setting_search_rules: { status: Boolean, description: String },
            setting_reputational_lists: { status: Boolean, description: String }
        }
    },
    management_analysis_sip: {
        name: String,
        element_settings: {
            read: { status: Boolean, description: String }
        }
    },
    management_security_event_management: {
        name: String,
        element_settings: {
            creat: { status: Boolean, description: String },
            editingInformation: { status: Boolean, description: String },
            statusChange: { status: Boolean, description: String },
            close: { status: Boolean, description: String },
            delete: { status: Boolean, description: String }
        }
    },
    management_network_interaction: {
        name: String,
        element_settings: {
            management_tasks_filter: {
                name: String,
                element_settings: {
                    read: { status: Boolean, description: String },
                    import: { status: Boolean, description: String },
                    delete: { status: Boolean, description: String }
                }
            },
            management_tasks_import: {
                name: String,
                element_settings: {
                    cancel: { status: Boolean, description: String },
                    stop: { status: Boolean, description: String },
                    resume: { status: Boolean, description: String }
                }
            },
            management_uploaded_files: {
                name: String,
                element_settings: {
                    status_change: { status: Boolean, description: String },
                    delete: { status: Boolean, description: String }
                }
            },
        }
    },
    management_search_tools: {
        name: String,
        element_settings: {
            read: { status: Boolean, description: String }
        }
    },
    management_decode_tools: {
        name: String,
        element_settings: {
            read: { status: Boolean, description: String }
        }
    },
    management_users: {
        name: String,
        element_settings: {
            create: { status: Boolean, description: String },
            read: { status: Boolean, description: String },
            edit: { status: Boolean, description: String },
            delete: { status: Boolean, description: String }
        }
    },
    management_groups: {
        name: String,
        element_settings: {
            create: { status: Boolean, description: String },
            read: { status: Boolean, description: String },
            edit: { status: Boolean, description: String },
            delete: { status: Boolean, description: String }
        }
    },
    management_objects_and_subjects: {
        name: String,
        element_settings: {
            create: { status: Boolean, description: String },
            read: { status: Boolean, description: String },
            edit: { status: Boolean, description: String },
            delete: { status: Boolean, description: String }
        }
    },
    management_ids_rules: {
        name: String,
        element_settings: {
            create: { status: Boolean, description: String },
            read: { status: Boolean, description: String },
            delete: { status: Boolean, description: String }
        }
    },
    management_geoip: {
        name: String,
        element_settings: {
            create: { status: Boolean, description: String },
            read: { status: Boolean, description: String },
            delete: { status: Boolean, description: String }
        }
    },
    management_search_rules: {
        name: String,
        element_settings: {
            create: { status: Boolean, description: String },
            read: { status: Boolean, description: String },
            edit: { status: Boolean, description: String },
            delete: { status: Boolean, description: String }
        }
    },
    management_reputational_lists: {
        name: String,
        element_settings: {
            create: { status: Boolean, description: String },
            read: { status: Boolean, description: String },
            edit: { status: Boolean, description: String },
            delete: { status: Boolean, description: String }
        }
    },
    management_events: {
        name: String,
        element_settings: {
            read: { status: Boolean, description: String },
            delete: { status: Boolean, description: String }
        }
    }
});

groupSchema.set('toObject', { getters: true });

module.exports = connection.model('group', groupSchema);