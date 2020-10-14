describe("Тест 1. Валидация параметров полученных от пользователя при выполнении задачи по фильтрации файлов", () => {
    it("Должна быть выполнена успешная валидация", () => {
        let obj = (require("../../libs/processing/routeSocketIo/validationFileFilteringParameters"))({
            source: 1221,
            dateTime: { start: 1589409240000, end: 1589456080633 },
            networkProtocol: "any",
            inputValue: {
                ip: {
                    any: [ "10.23.6.4", "65.11.3.61" ],
                    src: [ "1119.66.4.1" ],
                    dst: [ "10.12.33.1", "62.100.23.6" ],
                },
                nt: {
                    any: [],
                    src: [ "23.0.56.89/29" ],
                    dst: [],    
                },
                pt: {
                    any: [],
                    src: [ "e334" ],
                    dst: [ "446" ],    
                }, 
            },
        });

        if(obj.isValid){
            console.log(obj.filteringParameters.dateTime);
            console.log("IP");
            console.log(obj.filteringParameters.inputValue.ip);
            console.log("Network");
            console.log(obj.filteringParameters.inputValue.nw);
            console.log("Port");
            console.log(obj.filteringParameters.inputValue.pt);
        }
        
        console.log(obj.errorMsg);

        expect(obj.isValid).toBeTrue();
    });
});