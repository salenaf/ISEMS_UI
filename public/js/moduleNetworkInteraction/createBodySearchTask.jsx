import React from "react";
import { Button, Card, Col, Form, Row, Tooltip, OverlayTrigger } from "react-bootstrap";
import PropTypes from "prop-types";

import DatePicker from "react-datepicker";
import TokenInput from "react-customize-token-input";

import { helpers } from "../common_helpers/helpers.js";

class CreateProtocolList extends React.Component {
    constructor(props){
        super(props);
    }

    render(){
        return (
            <select className="custom-select custom-select-sm" onChange={this.props.handlerChosen} id="protocol_list">
                <option value="any">любой</option>
                <option value="tcp">tcp</option>
                <option value="udp">udp</option>
            </select>
        );
    }
}

CreateProtocolList.propTypes = {
    handlerChosen: PropTypes.func.isRequired,
};

export default class CreateBodySearchTask extends React.Component {
    constructor(props){
        super(props);

        this.state = {
            disabledButtonSearch: true,
            disabledRadioChosenTask: true,
            disabledRadioUploadedFile: true,
            disabledRadioUploadedAllFile: true,
            searchParameters: {
                cptp: false, //ConsiderParameterTaskProcessed — учитывать параметр TaskProcessed
                tp: false, //TaskProcessed — была ли задача отмечена клиентом API как завершенная
                id: 0, //ID - уникальный цифровой идентификатор источника
                sft: "", //StatusFilteringTask - статус задачи по фильтрации
                sfdt: "", //StatusFileDownloadTask - статус задачи по скачиванию файлов
                cpfid: false, //ConsiderParameterFilesDownloaded — учитывать параметр  FilesIsDownloaded
                fid: false, //FilesIsDownloaded — выполнялась ли выгрузка файлов
                cpafid: false, //ConsiderParameterAllFilesIsDownloaded -  учитывать параметр AllFilesIsDownloaded
                afid: false, //AllFilesIsDownloaded — все ли файлы были выгружены
                iaf: { //InformationAboutFiltering — поиск информации по результатам фильтрации
                    fif: false, //FilesIsFound — были ли найдены в результате фильтрации какие либо файлы
                    cafmin: 0, //CountAllFilesMin — минимальное общее количество всех найденных в результате фильтрации файлов
                    cafmax: 0, //CountAllFilesMax — максимальное общее количество всех найденных в результате фильтрации файлов
                    safmin: 0, //SizeAllFilesMin — минимальный общий размер всех найденных  в результате фильтрации файлов
                    safmax: 0, //SizeAllFilesMax — минимальный общий размер всех найденных  в результате фильтрации файлов
                },
                ifo: { //InstalledFilteringOption — искомые опции фильтрации
                    dt: { //DateTime -  дата и время фильтруемых файлов
                        s: new Date(), //Start - начальное дата и время фильтруемых файлов
                        e: new Date(), //End - конечное дата и время фильтруемых файлов
                    },
                    p: "any", //Protocol — транспортный протокол
                    nf: { //NetworkFilters — сетевые фильтры
                        ip: { //IP — фильтры для поиска по ip адресам
                            any: [], //Any — вы обе стороны
                            src: [], //Src — только как источник
                            dst: [], //Dst — только как получатель
                        },
                        pt: { //Port — фильтры для поиска по сетевым портам
                            any: [], //Any — вы обе стороны
                            src: [], //Src — только как источник
                            dst: [], //Dst — только как получатель
                        },
                        nw: { //Network — фильтры для поиска по подсетям
                            any: [], //Any — вы обе стороны
                            src: [], //Src — только как источник
                            dst: [], //Dst — только как получатель				
                        }
                    },
                },
            },
            inputFieldMinCfIsValid: false,
            inputFieldMinCfIsInvalid: false,
            inputFieldMaxCfIsValid: false,
            inputFieldMaxCfIsInvalid: false,
            inputFieldMinSfIsValid: false,
            inputFieldMinSfIsInvalid: false,
            inputFieldMaxSfIsValid: false,
            inputFieldMaxSfIsInvalid: false,
        };

        this.referenceObj = {
            cptp: false,
            tp: false,
            cpfid: false,
            fid: false,
            cpafid: false,
            afid: false,
            fif: false,
            id: 0,
            cafmin: 0,
            cafmax: 0,
            safmin: 0,
            safmax: 0,
            sft: "",
            sfdt: "",
            p: "any",
            currentDate: +this.state.searchParameters.ifo.dt.s,
        };

        this.getListSource = this.getListSource.bind(this);

        this.fieldChange = this.fieldChange.bind(this);
        this.handlerCheckbox = this.handlerCheckbox.bind(this);
        this.checkFieldChange = this.checkFieldChange.bind(this);
        this.handlerFieldInput = this.handlerFieldInput.bind(this);
        this.handlerRadioChosen = this.handlerRadioChosen.bind(this);
        this.handlerButtonSearch = this.handlerButtonSearch.bind(this);
        this.handlerChosenStatus = this.handlerChosenStatus.bind(this);
        this.handlerChosenSource = this.handlerChosenSource.bind(this);
        this.handlerChangeEndDate = this.handlerChangeEndDate.bind(this);
        this.handlerChangeStartDate = this.handlerChangeStartDate.bind(this);
        this.handlerCountAndSizeFiles = this.handlerCountAndSizeFiles.bind(this);
        this.handlerChosenProtocolList = this.handlerChosenProtocolList.bind(this);

        //this.testCheckObject.call(this);
    }

    testCheckObject(){
        let referenceObj = {
            cptp: false,
            tp: false,
            cpfid: false,
            fid: false,
            cpafid: false,
            afid: false,
            fif: false,
            id: 0,
            cafmin: 0,
            cafmax: 0,
            safmin: 0,
            safmax: 0,
            sft: "",
            sfdt: "",
            p: "any",
            currentDate: +new Date(),
        };

        let obj = {
            cptp: false, //ConsiderParameterTaskProcessed — учитывать параметр TaskProcessed
            tp: false, //TaskProcessed — была ли задача отмечена клиентом API как завершенная
            id: 0, //ID - уникальный цифровой идентификатор источника
            sft: "", //StatusFilteringTask - статус задачи по фильтрации
            sfdt: "", //StatusFileDownloadTask - статус задачи по скачиванию файлов
            cpfid: false, //ConsiderParameterFilesDownloaded — учитывать параметр  FilesIsDownloaded
            fid: false, //FilesIsDownloaded — выполнялась ли выгрузка файлов
            cpafid: false, //ConsiderParameterAllFilesIsDownloaded -  учитывать параметр AllFilesIsDownloaded
            afid: false, //AllFilesIsDownloaded — все ли файлы были выгружены
            iaf: { //InformationAboutFiltering — поиск информации по результатам фильтрации
                fif: false, //FilesIsFound — были ли найдены в результате фильтрации какие либо файлы
                cafmin: 0, //CountAllFilesMin — минимальное общее количество всех найденных в результате фильтрации файлов
                cafmax: 0, //CountAllFilesMax — максимальное общее количество всех найденных в результате фильтрации файлов
                safmin: 0, //SizeAllFilesMin — минимальный общий размер всех найденных  в результате фильтрации файлов
                safmax: 0, //SizeAllFilesMax — минимальный общий размер всех найденных  в результате фильтрации файлов
            },
            ifo: { //InstalledFilteringOption — искомые опции фильтрации
                dt: { //DateTime -  дата и время фильтруемых файлов
                    s: new Date(), //Start - начальное дата и время фильтруемых файлов
                    e: new Date(), //End - конечное дата и время фильтруемых файлов
                },
                p: "any", //Protocol — транспортный протокол
                nf: { //NetworkFilters — сетевые фильтры
                    ip: { //IP — фильтры для поиска по ip адресам
                        any: [], //Any — вы обе стороны
                        src: [], //Src — только как источник
                        dst: [], //Dst — только как получатель
                    },
                    pt: { //Port — фильтры для поиска по сетевым портам
                        any: [], //Any — вы обе стороны
                        src: [], //Src — только как источник
                        dst: [], //Dst — только как получатель
                    },
                    nw: { //Network — фильтры для поиска по подсетям
                        any: [], //Any — вы обе стороны
                        src: [], //Src — только как источник
                        dst: [], //Dst — только как получатель				
                    }
                },
            },
        };

        let recursiveLoopFunc = (data) => {
            for(let n in data){
                if(Array.isArray(data[n])){
                    console.log(`value: '${n}' is ARRAY, ${(data[n].length === 0)? "ARRAY is empty": "ARRAY is not empty"}`);
                    console.log(data[n]);

                    if(data[n].length > 0){
                        console.log(` -= VALUE: '${n}' =- UPDATED`);
                    }                        

                    continue;
                }
                if(typeof data[n] === "object"){
                    if(n === "s" || n === "e"){
                        //                        console.log(`value: '${n}' is DATE, ${()? "DATE is equal" : "DATE is not equal"}`);
                        console.log(+data[n]);
                        console.log(`current date: ${referenceObj.currentDate}`);

                        if(+data[n] !== referenceObj.currentDate){
                            console.log(` -= VALUE: '${n}' =- UPDATED TIME`);
                        }                        
                    } else {
                        console.log(`value: '${n}' is OBJECT`);
    
                        recursiveLoopFunc(data[n]);
                    }
                } else {
                    console.log(`=== value: '${n}' ANY TYPE`);

                    if(data[n] !== referenceObj[n]){
                        console.log(` -= VALUE: '${n}' =- UPDATED`);
                    }
                }
            }
        };

        /**
 * Протестировать и отладить эту функцию.
 * Она нужна для отслеживания изменения пользователем 
 * параметров поискового запроса. Отличие параметров поискового
 * запроса от значений по умолчанию. 
 * Если какое либо значение отличается от значения по умолчанию
 * делать кнопку 'поиск' активной. 
 * 
 * Сделать проверку поля 'ip адрес, порт или подсеть' основываясь
 * на regexp как просто для ip адрес, порт или подсеть так и с
 * использованием приставок src и dst.
 */

        recursiveLoopFunc(obj);
    }

    handlerChosenSource(e){
        console.log("func 'handlerChosenSource', START...");
        console.log(`был выбран источник с ID '${+(e.target.value)}'`);

        let objCopy = Object.assign({}, this.state.searchParameters);
        objCopy.id = +(e.target.value);
        this.setState({ searchParameters: objCopy });

        this.fieldChange(+(e.target.value), "id");
    }

    handlerChosenStatus(e){
        console.log("func 'handlerChosenStatus', START...");
        console.log(`тип статуса '${e.target.name}', статус '${e.target.value}'`);

        let elemName = "sft";

        let objCopy = Object.assign({}, this.state.searchParameters);
        switch (e.target.name) {
        case "list_status_filtration":
            objCopy.sft = e.target.value;
            break;

        case "list_status_download":
            elemName = "sfdt";
            objCopy.sfdt = e.target.value; 
            break;
        }

        this.setState({ searchParameters: objCopy });

        this.fieldChange(e.target.value, elemName);
    }

    handlerChosenProtocolList(e){
        console.log("func 'handlerChosenProtocolList', START...");
        console.log(`был выбран сетевой протокол '${e.target.value}'`);

        let objCopy = Object.assign({}, this.state.searchParameters);
        objCopy.ifo.p = e.target.value;
        this.setState({ searchParameters: objCopy });

        this.fieldChange(e.target.value, "p");
    }

    handlerCheckbox(e){
        console.log("func 'handlerCheckbox', START...");
        console.log(` checked = ${e.target.checked}`);
        console.log(`name = '${e.target.name}'`);

        let objCopy = Object.assign({}, this.state.searchParameters);
        let elemName = "";

        switch (e.target.name) {
        case "task_checkbox":
            elemName = "cptp";
            if(e.target.checked){
                objCopy.cptp = true;
                this.setState({ 
                    searchParameters: objCopy,
                    disabledRadioChosenTask: false, 
                });
            } else {
                objCopy.cptp = false;
                this.setState({ 
                    searchParameters: objCopy,
                    disabledRadioChosenTask: true, 
                });
            }       
            break;

        case "file_uploaded_check":
            elemName = "cpfid";
            if(e.target.checked){
                objCopy.cpfid = true;
                this.setState({ 
                    searchParameters: objCopy,
                    disabledRadioUploadedFile: false, 
                });
            } else {
                objCopy.cpfid = false;
                this.setState({ 
                    searchParameters: objCopy,
                    disabledRadioUploadedFile: true, 
                });
            }       
            break;

        case "all_file_uploaded_check":
            elemName = "cpafid";
            if(e.target.checked){
                objCopy.cpafid = true;
                this.setState({ 
                    searchParameters: objCopy,
                    disabledRadioUploadedAllFile: false, 
                });
            } else {
                objCopy.cpafid = false;
                this.setState({ 
                    searchParameters: objCopy,
                    disabledRadioUploadedAllFile: true, 
                });
            } 
            break;

        case "files_found":
            elemName = "fif";
            if(e.target.checked){
                objCopy.iaf.fif = true;
            } else {
                objCopy.iaf.fif = false;
            }
            this.setState({ searchParameters: objCopy });
            break;
        }

        this.fieldChange(e.target.checked, elemName);
    }

    handlerRadioChosen(e){
        console.log("func 'handlerRadioChosen', START...");
        console.log(`radio chosen '${e.target.value}'`);

        let objCopy = Object.assign({}, this.state.searchParameters);
        let elemName = "";

        switch (e.target.name) {
        case "chose_task_complete": 
            objCopy.tp = (e.target.value === "true") ? true: false;    
            elemName = "tp";
            break;
        
        case "chose_uploaded_file":
            objCopy.fid = (e.target.value === "true") ? true: false;
            elemName = "fid";
            break;
        
        case "chose_uploaded_all_file":
            objCopy.afid = (e.target.value === "true") ? true: false;
            elemName = "afid";
            break;
        }

        this.setState({ searchParameters: objCopy });

        this.fieldChange(((e.target.value === "true") ? true: false), elemName);
    }

    handlerButtonSearch(){
        console.log("func 'handlerButtonSearch', START...");
        console.log(this.state.searchParameters);

        if(this.checkFieldChange()){
            console.log("Изменений НЕТ");

            this.setState({ disabledButtonSearch: true });

            return;
        }

        console.log("Изменения ЕСТЬ");
    }

    handlerCountAndSizeFiles(e){
        console.log("func 'handlerCountAndSizeFiles', START...");
        console.log(e.target.value);

        let objCopy = Object.assign({}, this.state.searchParameters);

        if(helpers.checkInputValidation({
            "name": "integer", 
            "value": e.target.value, 
        })){  
            let elemName = "";
            
            switch (e.target.name) {
            case "min_count_files":
                objCopy.iaf.cafmin = e.target.value;
                this.setState({ 
                    searchParameters: objCopy, 
                    inputFieldMinCfIsValid: true,
                    inputFieldMinCfIsInvalid: false,
                });
                elemName = "cafmin";

                break;
                            
            case "max_count_files":
                objCopy.iaf.cafmax = e.target.value;
                this.setState({ 
                    searchParameters: objCopy, 
                    inputFieldMaxCfIsValid: true,
                    inputFieldMaxCfIsInvalid: false,
                });
                elemName = "cafmax";
                    
                break;
                            
            case "min_size_files":
                objCopy.iaf.safmin = e.target.value;
                this.setState({ 
                    searchParameters: objCopy, 
                    inputFieldMinSfIsValid: true,
                    inputFieldMinSfIsInvalid: false,
                });
                elemName = "safmin";
                    
                break;
        
            case "max_size_files":
                objCopy.iaf.safmax = e.target.value;
                this.setState({ 
                    searchParameters: objCopy, 
                    inputFieldMaxSfIsValid: true,
                    inputFieldMaxSfIsInvalid: false,
                });
                elemName = "safmax";

                break;
            }

            this.fieldChange(e.target.value, elemName);
        } else {  
            switch (e.target.name) {
            case "min_count_files":
                objCopy.iaf.cafmin = 0;
                this.setState({ 
                    searchParameters: objCopy,
                    inputFieldMinCfIsValid: false,
                    inputFieldMinCfIsInvalid: (e.target.value !== "") ? true: false,
                });
    
                break;
                                
            case "max_count_files":
                objCopy.iaf.cafmax = 0;
                this.setState({ 
                    searchParameters: objCopy, 
                    inputFieldMaxCfIsValid: false,
                    inputFieldMaxCfIsInvalid: (e.target.value !== "") ? true: false,
                });
                        
                break;
                                
            case "min_size_files":
                objCopy.iaf.safmin = 0;
                this.setState({ 
                    searchParameters: objCopy, 
                    inputFieldMinSfIsValid: false,
                    inputFieldMinSfIsInvalid: (e.target.value !== "") ? true: false,
                });
                        
                break;
            
            case "max_size_files":
                objCopy.iaf.safmax = 0;
                this.setState({ 
                    searchParameters: objCopy, 
                    inputFieldMaxSfIsValid: false,
                    inputFieldMaxSfIsInvalid: (e.target.value !== "") ? true: false,
                });

                break;
            }
        }
    }

    handlerChangeStartDate(date){
        let objCopy = Object.assign({}, this.state.searchParameters);
        objCopy.ifo.dt.s = date;
        this.setState({ searchParameters: objCopy });

        this.fieldChange(date, "currentDate");
    }

    handlerChangeEndDate(date){
        let objCopy = Object.assign({}, this.state.searchParameters);
        objCopy.ifo.dt.e = date;
        this.setState({ searchParameters: objCopy });

        this.fieldChange(date, "currentDate");
    }

    handlerFieldInput(e){
        console.log("func 'handlerFieldInput', START...");
        console.log(e.target.value);
    }

    fieldChange(item, elemName){
        if(Array.isArray(item)){
            if(item.length > 0){
                this.setState({ disabledButtonSearch: false });
            }                        
        } else {
            if(typeof item === "object"){
                if(elemName === "currentDate"){
                    if(+item !== this.referenceObj.currentDate){
                        this.setState({ disabledButtonSearch: false });
                    }                        
                }
            } else {
                if(item !== this.referenceObj[elemName]){
                    this.setState({ disabledButtonSearch: false });
                }
            }
        }
    }

    checkFieldChange(){
        let changeIsExist = true;

        let recursiveLoopFunc = (data) => {
            for(let n in data){
                if(Array.isArray(data[n])){
                    if(data[n].length > 0){
                        changeIsExist = false;
                    }                        

                    continue;
                }

                if(typeof data[n] === "object"){
                    if(n === "s" || n === "e"){
                        if(+data[n] !== this.referenceObj.currentDate){
                            changeIsExist = false;
                        }                        
                    } else {  
                        recursiveLoopFunc(data[n]);
                    }
                } else {
                    if(data[n] !== this.referenceObj[n]){
                        changeIsExist = false;
                    }
                }
            }
        };  

        recursiveLoopFunc(this.state.searchParameters);

        return changeIsExist;
    }

    getListSource(){

        console.log("func 'getListSource', create source list...");

        return Object.keys(this.props.listSources).sort((a, b) => a < b).map((sourceID) => {
            let isDisabled = !(this.props.listSources[sourceID].connectStatus);          

            return (
                <option 
                    key={`key_sour_${this.props.listSources[sourceID].id}`} 
                    value={sourceID} 
                    disabled={isDisabled} >
                    {`${sourceID} ${this.props.listSources[sourceID].shortName}`}
                </option>
            );
        });
    }

    render(){
        return (
            <React.Fragment>
                <Card className="mb-2" body>
                    <Form.Row>
                        <Form.Group as={Col}>
                            <Form.Control onChange={this.handlerChosenSource} as="select" size="sm">
                                <option value={0}>источник</option>
                                {this.getListSource()}
                            </Form.Control>
                        </Form.Group>
                        <Form.Group as={Col}>
                            <Form.Control onChange={this.handlerChosenStatus} name="list_status_filtration" as="select" size="sm">
                                <option value="">статус фильтрации</option>
                                <option value="wait">готовится к выполнению</option>
                                <option value="refused">oтклонена</option>
                                <option value="execute">выполняется</option>
                                <option value="complete">завершена успешно</option>
                                <option value="stop">остановлена пользователем</option>
                            </Form.Control>
                        </Form.Group>
                        <Form.Group as={Col}>
                            <Form.Control onChange={this.handlerChosenStatus} name="list_status_download" as="select" size="sm">
                                <option value="">статус выгрузки файлов</option>
                                <option value="wait">готовится к выполнению</option>
                                <option value="refused">oтклонена</option>
                                <option value="execute">выполняется</option>
                                <option value="not executed">не выполнялась</option>
                                <option value="complete">завершена успешно</option>
                                <option value="stop">остановлена пользователем</option>
                            </Form.Control>
                        </Form.Group>
                        <Form.Group as={Col} className="mt-1 ml-3">
                            <Form inline>
                                <Form.Check type="checkbox" onClick={this.handlerCheckbox} name="task_checkbox"/>
                                <small className="ml-1">задача</small>
                                <Form.Check 
                                    custom 
                                    type="radio"
                                    onClick={this.handlerRadioChosen} 
                                    id="r_task_complete" 
                                    value="true" 
                                    label="" 
                                    className="mt-1 ml-3" 
                                    name="chose_task_complete" 
                                    disabled={this.state.disabledRadioChosenTask} />
                                <small className="ml-1">закрыта</small>
                                <Form.Check 
                                    custom 
                                    type="radio"
                                    onClick={this.handlerRadioChosen}  
                                    id="r_task_not_complete" 
                                    value="false" 
                                    label="" 
                                    className="mt-1 ml-3" 
                                    name="chose_task_complete"
                                    defaultChecked
                                    disabled={this.state.disabledRadioChosenTask} />
                                <small className="ml-1">открыта</small>
                            </Form>
                        </Form.Group>
                    </Form.Row>
                    <Form.Row>
                        <Form.Group as={Col} className="text-left">
                            <Form.Row className="ml-1">
                                <Form.Check type="checkbox" onClick={this.handlerCheckbox} name="files_found" className="mt-n2"/>
                                <small className="ml-1 mt-n2">файлы найдены</small>
                            </Form.Row>
                            <Form.Row className="ml-1">
                                <Form.Check type="checkbox" onClick={this.handlerCheckbox} name="file_uploaded_check"/>
                                <small className="ml-1">выгрузка выполнялась</small>
                                <Form.Check 
                                    custom 
                                    type="radio"
                                    onClick={this.handlerRadioChosen} 
                                    id="r_upload_file" 
                                    value="true"
                                    label="" 
                                    className="mt-1 ml-3" 
                                    name="chose_uploaded_file" 
                                    disabled={this.state.disabledRadioUploadedFile} />
                                <small className="ml-1">да</small>
                                <Form.Check 
                                    custom 
                                    type="radio"
                                    onClick={this.handlerRadioChosen} 
                                    id="r_not_upload_file" 
                                    value="false" 
                                    label="" 
                                    className="mt-1 ml-3" 
                                    name="chose_uploaded_file"
                                    defaultChecked
                                    disabled={this.state.disabledRadioUploadedFile} />
                                <small className="ml-1">нет</small>
                            </Form.Row>
                            <Form.Row className="ml-1">
                                <Form.Check type="checkbox" onClick={this.handlerCheckbox} name="all_file_uploaded_check"/>
                                <small className="ml-1">все файлы выгружены</small>
                                <Form.Check 
                                    custom 
                                    type="radio"
                                    onClick={this.handlerRadioChosen} 
                                    id="r_upload_all_file" 
                                    value="true" 
                                    label="" 
                                    className="mt-1 ml-3" 
                                    name="chose_uploaded_all_file" 
                                    disabled={this.state.disabledRadioUploadedAllFile} />
                                <small className="ml-1">да</small>
                                <Form.Check 
                                    custom 
                                    type="radio"
                                    onClick={this.handlerRadioChosen} 
                                    id="r_not_upload_all_file" 
                                    value="false" 
                                    label="" 
                                    className="mt-1 ml-3" 
                                    name="chose_uploaded_all_file"
                                    defaultChecked
                                    disabled={this.state.disabledRadioUploadedAllFile} />
                                <small className="ml-1">нет</small>
                            </Form.Row>
                        </Form.Group>
                        <Form.Group as={Col} className="text-left">
                            <small>найдено файлов</small>
                            <Form.Row>
                                <Form.Group as={Col}>
                                    <Form.Control 
                                        onChange={this.handlerCountAndSizeFiles} 
                                        isValid={this.state.inputFieldMinCfIsValid}
                                        isInvalid={this.state.inputFieldMinCfIsInvalid} 
                                        name="min_count_files" 
                                        type="input" 
                                        size="sm" 
                                        placeholder="min" />
                                </Form.Group>
                                <Form.Group as={Col}>
                                    <Form.Control 
                                        onChange={this.handlerCountAndSizeFiles} 
                                        isValid={this.state.inputFieldMaxCfIsValid}
                                        isInvalid={this.state.inputFieldMaxCfIsInvalid}
                                        name="max_count_files" 
                                        type="input" 
                                        size="sm" 
                                        placeholder="max" />
                                </Form.Group>
                            </Form.Row>
                        </Form.Group>
                        <Form.Group as={Col} className="text-left">
                            <small>общий размер найденных файлов</small>
                            <Form.Row>
                                <Form.Group as={Col}>
                                    <Form.Control 
                                        onChange={this.handlerCountAndSizeFiles} 
                                        isValid={this.state.inputFieldMinSfIsValid}
                                        isInvalid={this.state.inputFieldMinSfIsInvalid}
                                        name="min_size_files" 
                                        type="input" 
                                        size="sm" 
                                        placeholder="min" />
                                </Form.Group>
                                <Form.Group as={Col}>
                                    <Form.Control 
                                        onChange={this.handlerCountAndSizeFiles} 
                                        isValid={this.state.inputFieldMaxSfIsValid}
                                        isInvalid={this.state.inputFieldMaxSfIsInvalid}
                                        name="max_size_files" 
                                        type="input" 
                                        size="sm" 
                                        placeholder="max" />
                                </Form.Group>
                            </Form.Row>
                        </Form.Group>    
                    </Form.Row>                    
                    <Form.Row className="mt-n3">
                        <Col md={5}>
                            <Row>
                                <Col md={6}>
                                    <small className="mr-1">начальное время</small>
                                    <Form.Row>
                                        <DatePicker 
                                            className="form-control form-control-sm green-border"
                                            selected={this.state.searchParameters.ifo.dt.s}
                                            onChange={this.handlerChangeStartDate}
                                            maxDate={new Date()}
                                            showTimeInput
                                            selectsStart
                                            isClearable
                                            timeFormat="p"
                                            timeInputLabel="Time:"
                                            dateFormat="dd.MM.yyyy hh:mm aa" />
                                    </Form.Row>
                                </Col>
                                <Col md={6}>
                                    <small className="mr-1">конечное время</small>
                                    <Form.Row>
                                        <DatePicker 
                                            className="form-control form-control-sm red-border"
                                            selected={this.state.searchParameters.ifo.dt.e}
                                            onChange={this.handlerChangeEndDate}
                                            maxDate={new Date()}
                                            showTimeInput
                                            selectsEnd
                                            isClearable
                                            timeFormat="p"
                                            timeInputLabel="Time:"
                                            dateFormat="dd.MM.yyyy hh:mm aa" />
                                    </Form.Row>
                                </Col>
                            </Row>
                        </Col>
                        <Col md={2} className="text-right">
                            <small className="mr-1">сет. протокол</small>
                            <CreateProtocolList handlerChosen={this.handlerChosenProtocolList} />
                        </Col>
                        <Col md={5}>
                            <Form.Row className="ml-2">
                                <TokenInput 
                                    className="react-token-input"
                                    validator={() => {
                                        return "s"; //если пустая то ОК
                                        //если что то в строке есть то Error
                                    }}
                                    onInputValueChange={(value) => {
                                        console.log(value);
                                    }}
                                    onChange={this.handlerFieldInput}
                                    placeholder="ip адрес, порт или подсеть" />
                                <OverlayTrigger
                                    key="tooltip_question"
                                    placement="right"
                                    overlay={<Tooltip>Для указания направления ip адреса, сетевого порта или подсети, добавте src_ или dst_. Если нужно указать направление в обе стороны, ничего не пишется.</Tooltip>}>
                                    <a href="#">
                                        <img className="clickable_icon ml-1" src="../images/icons8-help-28.png" alt=""></img>
                                    </a>
                                </OverlayTrigger>
                            </Form.Row>
                        </Col>
                    </Form.Row>
                    <Row>
                        <Col className="text-right mt-4 mb-n2">
                            <Button 
                                size="sm" 
                                onClick={this.handlerButtonSearch} 
                                disabled={this.state.disabledButtonSearch}
                                variant="outline-primary">
                                поиск
                            </Button>
                        </Col>
                    </Row>
                </Card>
            </React.Fragment>
        );
    }
}

CreateBodySearchTask.propTypes = {
    socketIo: PropTypes.object.isRequired,
    listSources: PropTypes.object.isRequired,
};