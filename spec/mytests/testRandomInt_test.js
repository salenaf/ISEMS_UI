describe("Тест 1. Вывод произвольного числа", () => {
    it("Должно выводится произвольное число", () => {
        function randomInteger(min, max) {
            // получить случайное число от (min-0.5) до (max+0.5)
            let rand = min - 0.5 + Math.random() * (max - min + 1);
            return Math.round(rand);
        }

        for (let i = 0; i <= 10; i++) {
            console.log(`${i}. num = ${randomInteger(1, 1000)}`);
        }
    });
});