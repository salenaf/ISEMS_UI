"use strict";

const async = require("async");

const models = require("../../controllers/models");
const mongodbQueryProcessor = require("../../middleware/mongodbQueryProcessor");

module.exports = function(callback) {
    console.log("func 'informationForPageSOARules', START...");
    // Тута происходит магия О.о
    
    async.parallel({
        /* shortListRuleSOA:(callbackParallel) => {
            mongodbQueryProcessor.querySelect(
                models.modelSOARules, { 
                    isMany: true,
                    options: { 
                        _id: 0, 
                        __v: 0, 
                        sid: 0,
                        classType:0,  
                        msg:  0,
                        body:   0,     
                    },
                }, (err, list) => {
                    //console.log(list);
                    if(err) callbackParallel(err);
                    else callbackParallel(null, list);
                });
        },*/
        /*    findSid: function  (callbackParallel) {
            models.modelSOARules.find(
                {sid: 26900}, (err, document) => {
                    if(err) callbackParallel(err);
                    else callbackParallel(null, document);
                });
        },
         fidsSidIn: function(callbackParallel){
            mongodbQueryProcessor.querySelect(
                models.modelSOARules, { 
                    query: {sid: }
                },
                (err, list) => {
                    //console.log(list);
                    if(err) callbackParallel(err);
                    else callbackParallel(null, list);
                })
        }*/

        listCountClassType: function (callbackParallel) {
            models.modelSOARules.aggregate([//modelRulesIDS
                { $group: {
                    _id: "$classType",
                    count: { $sum: 1 }
                }},
                { $sort: { count: -1 }}
            ], (err, document) => {
                if(err) callbackParallel(err);
                else callbackParallel(null, document);
            });
        }
    },(err, listEntity) => {
        // console.log(listEntity);
        if (err) callback(err);
        else callback(null, listEntity);
    }
    ); 
    //callback(null, "exit");
};

