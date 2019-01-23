/**
 * Модуль обработки процессов поиска
 * 
 * Версия 0.1, дата релиза 29.11.2017
 */

'use strict';

export default function addFunctionProcessingSearchField() {
    $('#fieldSearchRule')
        .on('tokenfield:createdtoken', function(e) {

            checkChangeInputSid();
            let inputValue = e.attrs.value;
            if (!(/^\d+$/.test(inputValue))) {
                $(e.relatedTarget).addClass('invalid');
                var parentElement = document.getElementById('fieldSearchRule');
                parentElement.parentNode.parentNode.classList.remove('has-success');
                parentElement.parentNode.parentNode.classList.add('has-error');
            }
        })
        .on('tokenfield:removedtoken', function(e) {
            checkChangeInputSid();
        });
    $('#fieldSearchRule').tokenfield();
}

//проверка изменений в поле ввода
function checkChangeInputSid() {
    let divParentNode = document.getElementById('fieldSearchRule');
    let tokenInvalid = divParentNode.parentNode.getElementsByClassName('invalid');
    let token = divParentNode.parentNode.getElementsByClassName('token');

    if (token.length === 0) {
        divParentNode.parentNode.parentNode.classList.remove('has-error');
        divParentNode.parentNode.parentNode.classList.remove('has-success');
    }

    if ((tokenInvalid.length === 0) && (token.length > 0)) {
        divParentNode.parentNode.parentNode.classList.remove('has-error');
        divParentNode.parentNode.parentNode.classList.add('has-success');
    }
}