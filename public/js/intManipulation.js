'use strict';

//преобразование чисел к строкам
let intManipulation = {
    //строка из числа по 3 символа с прабелом
    intConvert: function(nLoad) {
        let newString = nLoad.toString();
        let sL = newString.length;
        let interimArray = [];
        let countCycles = Math.ceil((sL / 3));
        let num = 0;
        for (let i = 0; i < countCycles; i++) {
            interimArray.push(newString.charAt(sL - (3 + num)) + newString.charAt(sL - (2 + num)) + newString.charAt(sL - (1 + num)));
            num += 3;
        }
        interimArray.reverse();
        return interimArray.join(' ');
    },
    //строка с точкой
    intGetChunk: function(nLoad) {
        let newString = nLoad.toString();
        let sL = newString.length;

        let interimArray = [];
        let countCycles = Math.ceil((newString.length / 3));
        let num = 0;
        for (let i = 0; i < countCycles; i++) {

            interimArray.push(newString.charAt(sL - (3 + num)) + newString.charAt(sL - (2 + num)) + newString.charAt(sL - (1 + num)));
            num += 3;
        }
        interimArray.reverse();

        return interimArray[0] + '.' + interimArray[1][0] + interimArray[1][1];
    },

    changeInt: function(type, value) {
        let array = [
            ['', ' байт', ' бит'],
            [' тыс.', ' Кб', ' Кбит'],
            [' млн.', ' Мб', ' Мбит'],
            [' млрд.', ' Гб', ' Гбит'],
            ['', ' Тб', '']
        ];

        let stringName = '';
        if (type === 'pkt') stringName = 0;
        else if (type === 'bytes') stringName = 1;
        else if (type === 'bite') stringName = 2;

        if (value < 1000) return value + array[0][stringName];
        else if (1000 <= value && value < 1000000) return this.intGetChunk(value) + array[1][stringName];
        else if (1000000 <= value && value < 1000000000) return this.intGetChunk(value) + array[2][stringName];
        else if (1000000000 <= value && value < 1000000000000) return this.intGetChunk(value) + array[3][stringName];
        else if (value > 1000000000000 && type === 'bytes') return this.intGetChunk(value) + array[4][stringName];
        else return value;
    }
};

export { intManipulation };