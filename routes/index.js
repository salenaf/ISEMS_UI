/*
 * Модуль маршрутизации для запросов к HTTP серверу
 *
 * Версия 0.1, дата релиза 15.01.2019
 * */

'use strict';

const passport = require('passport');

const headerPage = require('./pages/elements/headerPage');
const globalObject = require('../configure/globalObject');
const writeLogFile = require('../libs/writeLogFile');
const usersSessionInformation = require('../libs/mongodb_requests/usersSessionInformation');
const checkAccessRightsExecute = require('../libs/check/checkAccessRightsExecute');
const changeAdministratorPassword = require('../libs/changeAdministratorPassword');

const processingManagementUsers = require('./pages/processing_http_request/processingManagementUsers');
const processingManagementGroups = require('./pages/processing_http_request/processingManagementGroups');
const processingManagementSources = require('./pages/processing_http_request/processingManagementSources');
const processingDownloadFileSourceSetting = require('../libs/processing/processing_downloaded_files/processingDownloadFileSourceSetting');

module.exports = function(app, socketIo) {
    const pages = require('./pages');

    const listPages = {
        '/': pages.mainPage,
        '/auth': pages.authenticate,
        '/analysis_sip': pages.analysisSIP,
        '/security_event_management': pages.securityEventManagement,
        '/network_interaction': pages.networkInteraction,
        '/decode_tools': pages.toolsDecode,
        '/search_tools': pages.toolsSearch,
        '/setting_users': pages.managementUsers,
        '/setting_groups': pages.managementGroups,
        '/setting_objects_and_subjects': pages.managementObjectsAndSubjects,
        '/setting_ids_rules': pages.managementIdsRules,
        '/setting_search_rules': pages.managementSearchRules,
        '/setting_geoip': pages.managementGeoIp,
        '/setting_reputational_lists': pages.managementReputationalLists
    };

    function isAuthenticated(req, res, next) {
        if (req.isAuthenticated()) next();
        else res.redirect('/auth');
    }

    app.post('/auth', passport.authenticate('local', {
        successRedirect: '/',
        failureRedirect: '/auth?username=error'
    }));

    app.get('/auth', (req, res) => {
        if (req.isAuthenticated()) pages.mainPage.call(null, req, res, socketIo);
        else listPages['/auth'].call(null, req, res);
    });

    app.get('/', isAuthenticated, (req, res) => {
        //добавляем идентификатор sessionID к сессионным данным о пользователе
        usersSessionInformation.setSessionID(req.session.passport.user, req.sessionID, err => {
            if (err) writeLogFile('error', err.toString());

            headerPage(req)
                .then(objHeader => {
                    listPages['/'].call(null, req, res, objHeader);
                }).catch(err => {
                    writeLogFile('error', err.toString());
                    res.render('500', {})
                });
        });
    });

    app.post('/change_password', isAuthenticated, (req, res) => {
        changeAdministratorPassword(req, jsonObj => {
            res.json(jsonObj).end();
        });
    });

    //АНАЛИЗ ПАКЕТОВ ИНФОРМАЦИОННОЙ БЕЗОПАСНОСТИ
    app.get('/analysis_sip', isAuthenticated, (req, res) => {
        headerPage(req)
            .then(objHeader => {
                try {
                    let isAccess = objHeader.menuSettings.analysis_sip.status;

                    if (!isAccess) throw new Error('Access denied')

                    listPages['/analysis_sip'].call(null, req, res, objHeader);
                } catch (err) {
                    res.render('403', {});
                }
            }).catch(err => {
                writeLogFile('error', err.toString());
                res.render('500', {})
            });
    });

    //УПРАВЛЕНИЕ СОБЫТИЯМИ ИНФОРМАЦИОННОЙ БЕЗОПАСНОСТИ
    app.get('/security_event_management', isAuthenticated, (req, res) => {
        headerPage(req)
            .then(objHeader => {
                try {
                    let isAccess = objHeader.menuSettings.security_event_management.status;

                    if (!isAccess) throw new Error('Access denied')

                    listPages['/security_event_management'].call(null, req, res, objHeader);
                } catch (err) {
                    res.render('403', {});
                }
            }).catch(err => {
                writeLogFile('error', err.toString());
                res.render('500', {})
            });
    });

    //СЕТЕВЫЕ ВЗАИМОДЕЙСТВИЯ
    app.get('/network_interaction', isAuthenticated, (req, res) => {
        headerPage(req)
            .then(objHeader => {
                try {
                    let isAccess = objHeader.menuSettings.network_interaction.status;

                    if (!isAccess) throw new Error('Access denied')

                    listPages['/network_interaction'].call(null, req, res, objHeader);
                } catch (err) {
                    res.render('403', {});
                }
            }).catch(err => {
                writeLogFile('error', err.toString());
                res.render('500', {})
            });
    });

    //РАЗДЕЛ ДЕКОДИРОВАНИЯ ИНФОРМАЦИИ
    app.get('/decode_tools', isAuthenticated, (req, res) => {
        headerPage(req)
            .then(objHeader => {

                console.log(objHeader.menuSettings);

                try {
                    let isAccess = objHeader.menuSettings.element_tools.submenu.decode_tools.status;

                    if (!isAccess) throw new Error('Access denied')

                    listPages['/decode_tools'].call(null, req, res, objHeader);
                } catch (err) {
                    res.render('403', {});
                }
            }).catch(err => {
                writeLogFile('error', err.toString());
                res.render('500', {})
            });
    });

    //РАЗДЕЛ ПОИСКА
    app.get('/search_tools', isAuthenticated, (req, res) => {
        headerPage(req)
            .then(objHeader => {
                try {
                    let isAccess = objHeader.menuSettings.element_tools.submenu.search_tools.status;

                    if (!isAccess) throw new Error('Access denied')

                    listPages['/search_tools'].call(null, req, res, objHeader);
                } catch (err) {
                    res.render('403', {});
                }
            }).catch(err => {
                writeLogFile('error', err.toString());
                res.render('500', {})
            });
    });

    //УПРАВЛЕНИЕ ГРУППАМИ ПОЛЬЗОВАТЕЛЕЙ
    app.get('/setting_groups', isAuthenticated, (req, res) => {
        headerPage(req)
            .then(objHeader => {
                try {
                    let isAccess = objHeader.menuSettings.element_settings.submenu.setting_groups.status;

                    if (!isAccess) throw new Error('Access denied')

                    listPages['/setting_groups'].call(null, req, res, objHeader);
                } catch (err) {
                    res.render('403', {});
                }
            }).catch(err => {
                writeLogFile('error', err.toString());
                res.render('500', {})
            });
    });

    //УПРАВЛЕНИЕ ПОЛЬЗОВАТЕЛЯМИ
    app.get('/setting_users', isAuthenticated, (req, res) => {
        headerPage(req)
            .then(objHeader => {
                try {
                    let isAccess = objHeader.menuSettings.element_settings.submenu.setting_users.status;

                    if (!isAccess) throw new Error('Access denied')

                    listPages['/setting_users'].call(null, req, res, objHeader);
                } catch (err) {
                    res.render('403', {});
                }
            }).catch(err => {
                writeLogFile('error', err.toString());
                res.render('500', {})
            });
    });

    //УПРАВЛЕНИЕ ПОЛЬЗОВАТЕЛЯМИ
    /*app.post('/setting_users', isAuthenticated, (req, res) => {
         if (!req.body.actionType) return;

         checkAccessRightsExecute({
             management: 'management_users',
             actionType: req.body.actionType,
             sessionId: req.sessionID
         }, (err, successfully) => {
             if (err) writeLogFile('error', err.toString());

             if (!successfully) {
                 writeLogFile('error', `not enough rights to perform the action (session ID: ${req.sessionID})`);

                 res.json({ type: 'danger', message: 'недостаточно прав для выполнения действия', action: '' }).end();
             } else {
                 processingManagementUsers(req, res, jsonObj => {
                     res.json(jsonObj).end();
                 });
             }
         });
     });*/

    //УПРАВЛЕНИЕ ИСТОЧНИКАМИ
    app.get('/setting_objects_and_subjects', isAuthenticated, (req, res) => {
        headerPage(req)
            .then(objHeader => {
                try {
                    let isAccess = objHeader.menuSettings.element_settings.submenu.setting_objects_and_subjects.status;

                    if (!isAccess) throw new Error('Access denied')

                    listPages['/setting_objects_and_subjects'].call(null, req, res, objHeader);
                } catch (err) {
                    res.render('403', {});
                }
            }).catch(err => {
                writeLogFile('error', err.toString());
                res.render('500', {})
            });
    });

    //УПРАВЛЕНИЕ ИСТОЧНИКАМИ
    /*app.post('/setting_objects_and_subjects', isAuthenticated, (req, res) => {
        if (!req.body.actionType) return;

        checkAccessRightsExecute({
            management: 'management_sources',
            actionType: req.body.actionType,
            sessionId: req.sessionID
        }, (err, successfully) => {
            if (err) writeLogFile('error', err.toString());

            if (!successfully) {
                writeLogFile('error', `not enough rights to perform the action (session ID: ${req.sessionID})`);

                res.json({ type: 'danger', message: 'недостаточно прав для выполнения действия', action: '' }).end();
            } else {
                processingManagementSources(req, res, socketIo, finalObj => {
                    res.json(finalObj).end();
                });
            }
        });
    });*/

    //УПРАВЛЕНИЕ ИСТОЧНИКАМИ (Экспорт XML файла с настройками источников)
    app.get('/export_file_setup_hosts', isAuthenticated, (req, res) => {
        return processingDownloadFileSourceSetting(req, res);
    });

    //УПРАВЛЕНИЕ ПРАВИЛАМИ СОА
    app.get('/setting_ids_rules', isAuthenticated, (req, res) => {
        headerPage(req)
            .then(objHeader => {
                try {
                    let isAccess = objHeader.menuSettings.element_settings.submenu.setting_ids_rules.status;

                    if (!isAccess) throw new Error('Access denied')

                    listPages['/setting_ids_rules'].call(null, req, res, objHeader);
                } catch (err) {
                    res.render('403', {});
                }
            }).catch(err => {
                writeLogFile('error', err.toString());
                res.render('500', {})
            });
    });

    //УПРАВЛЕНИЕ ПРАВИЛАМИ ПОИСКА
    app.get('/setting_search_rules', isAuthenticated, (req, res) => {
        headerPage(req)
            .then(objHeader => {
                try {
                    let isAccess = objHeader.menuSettings.element_settings.submenu.setting_search_rules.status;

                    if (!isAccess) throw new Error('Access denied')

                    listPages['/setting_search_rules'].call(null, req, res, objHeader);
                } catch (err) {
                    res.render('403', {});
                }
            }).catch(err => {
                writeLogFile('error', err.toString());
                res.render('500', {})
            });
    });

    //УПРАВЛЕНИЕ GeoIP
    app.get('/setting_geoip', isAuthenticated, (req, res) => {
        headerPage(req)
            .then(objHeader => {
                try {
                    let isAccess = objHeader.menuSettings.element_settings.submenu.setting_geoip.status;

                    if (!isAccess) throw new Error('Access denied')

                    listPages['/setting_geoip'].call(null, req, res, objHeader);
                } catch (err) {
                    res.render('403', {});
                }
            }).catch(err => {
                writeLogFile('error', err.toString());
                res.render('500', {})
            });
    });

    //УПРАВЛЕНИЕ РЕПУТАЦИОННЫМИ СПИСКАМИ
    app.get('/setting_reputational_lists', isAuthenticated, (req, res) => {
        headerPage(req)
            .then(objHeader => {
                try {
                    let isAccess = objHeader.menuSettings.element_settings.submenu.setting_reputational_lists.status;

                    if (!isAccess) throw new Error('Access denied')

                    listPages['/setting_reputational_lists'].call(null, req, res, objHeader);
                } catch (err) {
                    res.render('403', {});
                }
            }).catch(err => {
                writeLogFile('error', err.toString());
                res.render('500', {})
            });

        //получаем заголовок страницы
        headerPage(req, (err, objHeader) => {
            if (err) {
                writeLogFile('error', err.toString());

                pages.managementReputationalLists.call(null, req, res, {}, socketIo);
            } else {
                pages.managementReputationalLists.call(null, req, res, objHeader, socketIo);
            }
        });
    });

    //ВЫХОД
    app.get('/logout', (req, res) => {
        req.logOut();
        req.session.destroy();
        //удаляем сессионные данные о пользователе
        usersSessionInformation.delete(req.sessionID, err => {
            if (err) writeLogFile('error', err.toString());
        });

        if (typeof globalObject.getData('users', req.sessionID) === 'object') {
            globalObject.deleteData('users', req.sessionID);
        }

        res.redirect('/auth');
    });

    if (process.env.NODE_ENV !== 'development') {
        app.use(function(err, req, res, next) {
            res.render('500', {});
        });
    }
};