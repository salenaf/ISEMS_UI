Information Security Event Management System (ISEMS-UI) версия 1.3.0

/*** установка и настройка ***/
    Предварительная настройка СУБД MongoDB
    
    1. Создать БД и перейти в нее 
        use isems-ui
    
    2. Создать пользователя которому будет разрешен доступ к данной БД. Имя пользователя берется из config.json приложения
        db.createUser({
            user: "имя пользователя тоже что и в config.json",
            pwd: "пароль пользователя тот что и в config.json",
            roles: [{ role: "readWrite", db: "isems-ui" }],
            authenticationRestrictions: [{
                clientSource: ["127.0.0.1"],
                serverAddress: ["127.0.0.1"]
            }]
        })
