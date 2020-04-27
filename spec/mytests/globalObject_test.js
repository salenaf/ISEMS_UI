"use struct";

const globalObject = require("../../configure/globalObject");

describe("Тест 1. Проверяем удаление объекта из globalObject", function() {
    it("Объект должен быть удален, ошибки быть не должно", function() {

        let to = "testobject";
        let error = null;
        let isSuccess = false;
        //настраиваем хранилище задач выполняемые модулем
        globalObject.setData("tasks", "networkInteractionTaskList", {});
        globalObject.setData("tasks", "networkInteractionTaskList", to, { id: 1, date: +(new Date) });

        console.log("before");
        console.log(globalObject.getData("tasks", "networkInteractionTaskList"));

        try {
            isSuccess = globalObject.deleteData("tasks", "networkInteractionTaskList", to);

            console.log("after");
            console.log(globalObject.getData("tasks", "networkInteractionTaskList"));

        } catch (err) {
            error = err;
        }

        expect(isSuccess).toBeTrue();
        expect(error).toBeNull();
    });
});