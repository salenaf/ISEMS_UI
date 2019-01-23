'use strict';

import { managementIcon } from '../commons/managementIcon';
import sendData from './sendData';
import checkInputValidation from './checkInputValidation';
import getInputFieldIpAddress from './getInputFieldIpAddress';

export default function transmissionInformationSource() {
    function getFormElements() {
        return {
            'hostId': document.getElementsByName('hostId')[0],
            'shortNameHost': document.getElementsByName('shortNameHost')[0],
            'fullNameHost': document.getElementsByName('fullNameHost')[0],
            'intervalReceiving': document.getElementsByName('intervalReceiving')[0],
            'ipaddress': document.getElementsByName('ipaddress')[0]
        };
    }

    let obj = getFormElements();
    let objFinal = {};

    for (let elemName in obj) {
        if (obj[elemName] === null) continue;
        if (obj[elemName].value.length === 0) {
            managementIcon.showIcon(obj[elemName], false);
        } else {
            if (checkInputValidation(obj[elemName]) === true) {
                managementIcon.showIcon(obj[elemName], true);
                objFinal[elemName] = obj[elemName].value;
            } else {
                managementIcon.showIcon(obj[elemName], false);
            }
        }
    }

    let rangeIpNetwork = getInputFieldIpAddress();

    if (rangeIpNetwork.length !== 0) objFinal['rangeIpNetwork'] = rangeIpNetwork;
    if (Object.keys(objFinal).length !== 6) return;

    objFinal.type = 'action';
    sendData({ actionType: 'create', settings: objFinal });

    $('#modalAddEditHosts').modal('hide');
}