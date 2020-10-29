"use struct";

/**
 * Добавляет информацию о версии и дате релиза ПО ISEMS-NIH_slave
 * 
 * @param {*} data - параметры полученные от модуля ISEMS-NIH_master
 * @param {*} callback - функция обратного вызова
 */
module.exports = function(data, callback){
    require("../../../middleware/mongodbQueryProcessor").queryUpdate(
        require("../../../controllers/models").modelSourcesParameter, {
            query: { source_id: data.id },
            update: {
                "information_about_app.version": data.av,
                "information_about_app.date": data.ard,
            }
        }, (err) => {
            if(err) callback(err);
            else callback(null);
        });
};