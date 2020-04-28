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

describe("Тест 2. Проверяем метод hasDate объекта globalObject", function() {
    globalObject.setData("sources", "1000", { descripton: "testobj" });

    it("Значение ДОЛЖНО быть найдено", () => {
        expect(globalObject.hasData("sources", "1000")).toBeTrue();
    });

    it("Значение description ДОЛЖНО быть найдено", () => {
        expect(globalObject.hasData("sources", "1000", "descripton")).toBeTrue();
    });

    it("Значение НЕ ДОЛЖНО быть найдено", () => {
        expect(globalObject.hasData("sources", "1001")).toBeFalse();
    });
});

describe("Тест 3. Проверяем метод для изменения состояния сетевого соединения", function(){
    it("Состояние соединения должно быть успешно изменено", () => {
        globalObject.setData("sources", "1313", {
            shortName: "source1313",
            description: "",
            connectStatus: false,
            connectTime: 0,
            id: "",
        });

        globalObject.modifyData("sources", "1313", [[ "connectStatus", true ]]);

        let s = globalObject.getData("sources", "1313");

        expect(s.connectStatus).toBeTrue();
    });
});