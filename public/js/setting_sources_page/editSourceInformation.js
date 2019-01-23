/**
 * Модуль формирующий модальное окно редактирования источника
 * 
 * Версия 0.1, дата релиза 30.11.2017
 */

'use strict';

import { managementIcon } from '../commons/managementIcon';
import checkInputValidation from './checkInputValidation';
import getInputFieldIpAddress from './getInputFieldIpAddress';
import checkChangeInputIpAddress from './checkChangeInputIpAddress';

export default function editSourceInformation(obj) {
    function transmissionData(object) {
        let xhr = new XMLHttpRequest();
        xhr.open('POST', 'setting_sources', true);
        xhr.setRequestHeader('Content-Type', 'application/json');

        xhr.send(JSON.stringify(object));

        xhr.onreadystatechange = function() {
            if (xhr.readyState === 4 && xhr.status === 200) {
                try {
                    let resObj = JSON.parse(xhr.responseText);

                    if (typeof resObj.message !== 'undefined') {
                        common.showNotify(resObj.type, resObj.message);
                        if (resObj.action === 'reload') setTimeout(function() {
                            window.location.reload();
                        }, 3000);
                    }
                } catch (err) {
                    common.showNotify('warning', 'некорректный JSON объект');
                }
            }
        };
    }

    function checkEditInformation() {
        let objFinal = {};
        let sourceId = document.querySelector('#modalEditHosts span[data-source-id]').dataset.sourceId;
        let errorClass = document.querySelectorAll('#modalEditHosts .has-error');

        objFinal.hostId = sourceId;
        let elemInputFields = document.querySelectorAll('#modalEditHosts .modal-body .form-group input');

        elemInputFields.forEach(function(item) {
            if (item.value === '') return;

            if (item.name === '') {
                let rangeIpNetwork = getInputFieldIpAddress();
                if (rangeIpNetwork.length !== 0) objFinal.rangeIpNetwork = rangeIpNetwork;
            } else {
                objFinal[item.name] = item.value;
            }
        });

        if (errorClass.length > 0) return;
        if (typeof objFinal.rangeIpNetwork === 'undefined') return;

        objFinal.type = 'action';

        transmissionData({ actionType: 'edit', settings: objFinal });

        $('#modalEditHosts').modal('hide');
    }

    let inputNames = {
        'shortNameHost': 'short_name',
        'fullNameHost': 'detailed_description',
        'intervalReceiving': 'update_frequency',
        'ipaddress': 'ipaddress'
    };

    let newModalWindow = document.getElementById('modalEditHosts');
    if (newModalWindow === null) {
        let divModalWindow = document.getElementById('modalAddEditHosts');
        newModalWindow = divModalWindow.cloneNode(true);

        newModalWindow.removeAttribute('id');
        newModalWindow.setAttribute('id', 'modalEditHosts');

        document.getElementById('container').appendChild(newModalWindow);
    }

    newModalWindow.querySelector('.modal-header .modal-title').innerHTML = 'Источник №' + obj.id;

    let fieldHidden = document.createElement('span');
    fieldHidden.classList.add('hidden');
    fieldHidden.setAttribute('name', 'hiddenFieldSourceId');
    fieldHidden.setAttribute('data-source-id', obj.id);

    newModalWindow.querySelector('.modal-header .modal-title').appendChild(fieldHidden);

    let elemForm = newModalWindow.querySelector('.modal-body > .form-horizontal');
    if (elemForm.firstElementChild.firstElementChild.getAttribute('for') === 'hostId') {
        elemForm.removeChild(elemForm.firstElementChild);
    }

    let inputs = elemForm.querySelectorAll('input');
    for (let nameInput in inputNames) {
        inputs.forEach((item) => {
            if (item.name === nameInput) {
                item.value = obj[inputNames[nameInput]];
                managementIcon.removeIcon(item);
            }
        });
    }

    let inputNetworkSegmentRange = elemForm.querySelectorAll('.form-group');

    inputNetworkSegmentRange.forEach((item) => {
        if (item.firstElementChild.getAttribute('for') === 'segmentRange') {
            item.removeChild(item.firstElementChild.nextElementSibling);

            let div = document.createElement('div');
            div.classList.add('col-sm-5', 'col-md-5', 'col-lg-5');

            let divForm = document.createElement('div');
            divForm.classList.add('form-group');

            let input = document.createElement('input');
            input.setAttribute('type', 'text');
            input.classList.add('form-control', 'input-xs');
            input.setAttribute('id', 'networkRange');

            let span = document.createElement('span');
            span.classList.add('glyphicon', 'form-control-feedback');

            divForm.appendChild(input);
            div.appendChild(divForm);
            div.appendChild(span);
            item.appendChild(div);
        }
    });

    //добавляем обработчик на поле ввода IP-адресов или подсетей модального окна
    $('#networkRange').
        on('tokenfield:createdtoken', function(e) {
            checkChangeInputIpAddress();
            let patternIp = new RegExp('^((25[0-5]|2[0-4]\\d|[01]?\\d\\d?)[.]){3}(25[0-5]|2[0-4]\\d|[01]?\\d\\d?)$');
            let patternNet = new RegExp('^((25[0-5]|2[0-4]\\d|[01]?\\d\\d?)[.]){3}(25[0-5]|2[0-4]\\d|[01]?\\d\\d?)/[0-9]{1,2}$');
            let inputValue = e.attrs.value;
            let isNetwork = inputValue.split('/');

            if ((isNetwork.length > 0) && (isNetwork[1] > 32)) {
                $(e.relatedTarget).addClass('invalid');
                let parentElement = document.getElementById('networkRange');
                parentElement.parentNode.parentNode.classList.remove('has-success');
                parentElement.parentNode.parentNode.classList.add('has-error');
                return;
            }

            let validIp = patternIp.test(inputValue);
            let validNet = patternNet.test(inputValue);

            if (!validIp && !validNet) {
                $(e.relatedTarget).addClass('invalid');
                let parentElement = document.getElementById('networkRange');
                parentElement.parentNode.parentNode.classList.remove('has-success');
                parentElement.parentNode.parentNode.classList.add('has-error');
            }
        }).on('tokenfield:removedtoken', function(e) {
            checkChangeInputIpAddress();
        }).tokenfield({}).tokenfield('setTokens', obj.range_monitored_addresses);

    //добавляем обработчик на кнопку 'сохранить'
    (function() {
        let buttonSave = document.querySelector('#modalEditHosts #buttonSave');
        if (buttonSave !== null) {
            document.querySelector('#modalEditHosts #buttonSave').addEventListener('click', checkEditInformation);
        }
    })();

    //добавляем обработчики на поля ввода модального окна редактирования источника
    (function() {
        let inputsModalAddEditHosts = document.querySelectorAll('#modalEditHosts .form-horizontal input');
        inputsModalAddEditHosts.forEach((element) => {
            if (!(element.hasAttribute('id')) && !(element.hasAttribute('tabindex'))) {
                element.addEventListener('blur', (e) => {
                    let elem = e.target;
                    managementIcon.showIcon(elem, checkInputValidation(elem));
                });
            }
        });
    })();

    $('#modalEditHosts').modal('show');
}