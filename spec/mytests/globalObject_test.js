"use struct";

const globalObject = require("../../configure/globalObject");

let list = {
    "1001": {
        shortName: "Test Source",
        description: "дополнительное описание для источника",
        connectStatus: false,
        connectTime: 0,
        id: "f87b15cfa172955c305df67386a6f09c"
    },
    "1010": {
        shortName: "Test Source",
        description: "дополнительное описание для источника",
        connectStatus: false,
        connectTime: 0,
        id: "04b0b843a33ab16418a50ae6dc84f92e"
    },
    "1221": {
        shortName: "Test sensor 1221",
        description: "",
        connectStatus: false,
        connectTime: 0,
        id: "6b5446454ab57a77c80150b39a4bd"
    },
    "3000": {
        shortName: "3000 Kosmonaft",
        description: "",
        connectStatus: false,
        connectTime: 0,
        id: "2a23a9602cb4549585b64b79093"
    },
    "3001": {
        shortName: "3001 Kosmonaft",
        description: "",
        connectStatus: false,
        connectTime: 0,
        id: "215d7b1db7c9235c73c15387ab7b9"
    },
    "3003": {
        shortName: "Test 1",
        description: "",
        connectStatus: false,
        connectTime: 0,
        id: "517676111897c87cd5114626350a"
    },
    "3004": {
        shortName: "Test2",
        description: "",
        connectStatus: false,
        connectTime: 0,
        id: "0d05026dbc830a974c916693db3a4"
    },
    "4000": {
        shortName: "VS Major",
        description: "",
        connectStatus: false,
        connectTime: 0,
        id: "c1218986abd372d4467053507cd3"
    },
    "4001": {
        shortName: "VS secondary",
        description: "",
        connectStatus: false,
        connectTime: 0,
        id: "9c8791630dbb44d36499a3a1b294"
    },
    "4003": {
        shortName: "VS secondary 2",
        description: "",
        connectStatus: false,
        connectTime: 0,
        id: "93729d27b3d2245d1b4aba488847"
    },
    "4005": {
        shortName: "VS major 1",
        description: "",
        connectStatus: false,
        connectTime: 0,
        id: "07acb39a213d04782208684615318"
    },
    "4006": {
        shortName: "VSffnii",
        description: "",
        connectStatus: false,
        connectTime: 0,
        id: "38d3c5d6a64dcb741959b3692d3d"
    },
    "4007": {
        shortName: "VSnfinednf",
        description: "",
        connectStatus: false,
        connectTime: 0,
        id: "0dc2b09a53bdc0d0d1937a5b7d713b"
    },
    "4008": {
        shortName: "TestSource",
        description: "",
        connectStatus: false,
        connectTime: 0,
        id: "2025776dc236cd917520409c112b14"
    },
    "4009": {
        shortName: "TYYnhh",
        description: "",
        connectStatus: false,
        connectTime: 0,
        id: "dd666dd15b29d0926735734143a6"
    },
    "4010": {
        shortName: "RTtdcttt",
        description: "",
        connectStatus: false,
        connectTime: 0,
        id: "b9077856c8a6b197c0ba30c3a18c"
    },
    "4011": {
        shortName: "TsteSource",
        description: "",
        connectStatus: false,
        connectTime: 0,
        id: "255cc89059136250c29b47585d2dc5"
    },
    "4012": {
        shortName: "GHtgdhhs",
        description: "",
        connectStatus: false,
        connectTime: 0,
        id: "395499079692817b050a756abc79d"
    },
    "4013": {
        shortName: "NNdndnjdj",
        description: "",
        connectStatus: false,
        connectTime: 0,
        id: "63d94a9240a29c8116d818c04d53"
    },
    "10010": {
        shortName: "MinTorgProm 1",
        description: "",
        connectStatus: false,
        connectTime: 0,
        id: "41a9a8ab6b3dbb9d0c01cd8db697"
    },
    "10011": {
        shortName: "MinTorgProm 2",
        description: "",
        connectStatus: false,
        connectTime: 0,
        id: "2bab276d2708855094d41a83150471"
    },
    "10020": {
        shortName: "RosAtom COD 1",
        description: "",
        connectStatus: false,
        connectTime: 0,
        id: "0681690b573111c448b0c4cd11034"
    },
    "10021": {
        shortName: "RosAtom COD 2",
        description: "",
        connectStatus: false,
        connectTime: 0,
        id: "83a8b7b48267b7315216694907cd8"
    },
    "10030": {
        shortName: "RosCosmos COD 1",
        description: "",
        connectStatus: false,
        connectTime: 0,
        id: "633461b9c3605b1c33c92c61b6362"
    },
    "10031": {
        shortName: "RosCosmos COD 2",
        description: "",
        connectStatus: false,
        connectTime: 0,
        id: "77c0171b248549a78ad0bac6622c"
    },
    "13000": {
        shortName: "Tyyuo",
        description: "",
        connectStatus: false,
        connectTime: 0,
        id: "34db299187056b9d562c2162b522"
    },
    "13001": {
        shortName: "Hjkkkk",
        description: "",
        connectStatus: false,
        connectTime: 0,
        id: "b8a476cc30821514204bb979b49a"
    },
    "40008": {
        shortName: "TestSource",
        description: "",
        connectStatus: false,
        connectTime: 0,
        id: "4318dc25101c79945d2d034777069"
    }
};

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

/*describe("Тест 2. Проверяем метод hasDate объекта globalObject", function() {
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
});*/

describe("Тест 3. Проверяем метод для изменения состояния сетевого соединения", function(){
    it("Состояние соединения должно быть успешно изменено", () => {
        for(let source in list){
            globalObject.setData("sources", source, list[source]);
        }        

        let sb = globalObject.getData("sources", "1221");
        
        console.log(sb);

        globalObject.modifyData("sources", 1221, [[ "connectStatus", true ], [ "connectTime", +(new Date) ]]);

        let sa = globalObject.getData("sources", "1221");
        
        console.log(sa);

        expect(sa.connectStatus).toBeTrue();
    });
});
