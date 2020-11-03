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

        this.sp = {
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

        this.state = {
            disabledButtonSearch: true,
            disabledRadioChosenTask: true,
            disabledRadioUploadedFile: true,
            disabledRadioUploadedAllFile: true,
            searchParameters: Object.assign({}, this.sp),
            errorFieldInput: "",
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

        this.checkInput = this.checkInput.bind(this);
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
        this.handlerFieldInputValidator = this.handlerFieldInputValidator.bind(this);
    }

    handlerChosenSource(e){
        let objCopy = Object.assign({}, this.state.searchParameters);
        objCopy.id = +(e.target.value);
        this.setState({ searchParameters: objCopy });

        this.fieldChange(+(e.target.value), "id");
    }

    handlerChosenStatus(e){
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
        let objCopy = Object.assign({}, this.state.searchParameters);
        objCopy.ifo.p = e.target.value;
        this.setState({ searchParameters: objCopy });

        this.fieldChange(e.target.value, "p");
    }

    handlerCheckbox(e){
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
        if(this.checkFieldChange()){
            this.setState({ disabledButtonSearch: true });

            return;
        }

        let sp = this.state.searchParameters;
        sp.ifo.dt.s = +(this.state.searchParameters.ifo.dt.s);
        sp.ifo.dt.e = +(this.state.searchParameters.ifo.dt.e);

        this.props.handlerButtonSearch(sp.ifo.nf);
        this.props.socketIo.emit("network interaction: start search task", {
            actionType: "search tasks",
            arguments: sp,
        });
    }

    handlerCountAndSizeFiles(e){
        let objCopy = Object.assign({}, this.state.searchParameters);

        if(helpers.checkInputValidation({
            "name": "integer", 
            "value": e.target.value, 
        })){  
            let elemName = "";
            
            switch (e.target.name) {
            case "min_count_files":
                objCopy.iaf.cafmin = +e.target.value;
                this.setState({ 
                    searchParameters: objCopy, 
                    inputFieldMinCfIsValid: true,
                    inputFieldMinCfIsInvalid: false,
                });
                elemName = "cafmin";

                break;
                            
            case "max_count_files":
                objCopy.iaf.cafmax = +e.target.value;
                this.setState({ 
                    searchParameters: objCopy, 
                    inputFieldMaxCfIsValid: true,
                    inputFieldMaxCfIsInvalid: false,
                });
                elemName = "cafmax";
                    
                break;
                            
            case "min_size_files":
                objCopy.iaf.safmin = +e.target.value;
                this.setState({ 
                    searchParameters: objCopy, 
                    inputFieldMinSfIsValid: true,
                    inputFieldMinSfIsInvalid: false,
                });
                elemName = "safmin";
                    
                break;
        
            case "max_size_files":
                objCopy.iaf.safmax = +e.target.value;
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

    handlerFieldInputValidator(data){
        if(data.includes("src_")){
            let { err: err } = this.checkInput(data.substr((data.indexOf("src_")) + 4));
            if(err !== null){
                return err;
            }

            return;
        } else if(data.includes("dst_")){
            let { err: err } = this.checkInput(data.substr((data.indexOf("dst_")) + 4));
            if(err !== null){
                return err;
            }

            return;
        } else {
            let { err: err } = this.checkInput(data);
            if(err !== null){
                return err;
            }

            return;
        }
    }

    handlerFieldInput(data){
        let nf = {
            ip: { any: [], src: [], dst: [] },
            pt: { any: [], src: [], dst: [] },
            nw: { any: [], src: [], dst: [] },
        };
        let objCopy = Object.assign({}, this.state.searchParameters);
        data.forEach((item) => {
            if(item.value.includes("src_")){
                let { err: err, type: t, value: v } = this.checkInput(item.value.substr((item.value.indexOf("src_")) + 4));
                if(err === null){
                    nf[t].src.push(v);

                    this.fieldChange(nf[t].src, "");
                }

            } else if(item.value.includes("dst_")){
                let { err: err, type: t, value: v } = this.checkInput(item.value.substr((item.value.indexOf("dst_")) + 4));
                if(err === null){
                    nf[t].dst.push(v);

                    this.fieldChange(nf[t].dst, "");
                }
            } else {
                let { err: err, type: t, value: v } = this.checkInput(item.value);
                if(err === null){
                    nf[t].any.push(v);

                    this.fieldChange(nf[t].any, "");
                }
            }
        });

        objCopy.ifo.nf = nf;
        this.setState({ searchParameters: objCopy });
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

    checkInput(value){   
        if(value.includes(".")){
            if(value.includes("/")){
                if(helpers.checkInputValidation({
                    "name": "network", 
                    "value": value, 
                })){    
                    return { err: null, type: "nw", value: value };
                } else {  
                    return { err: new Error("network invalid"), type: "", value: "" };
                }
            } else {
                if(helpers.checkInputValidation({
                    "name": "ipaddress", 
                    "value": value, 
                })){                  
                    return { err: null, type: "ip", value: value };
                } else {  
                    return { err: new Error("ipaddress invalid"), type: "", value: "" };
                }
            }
        } else {
            if(helpers.checkInputValidation({
                "name": "port", 
                "value": value, 
            })){
                return { err: null, type: "pt", value: value };
            } else {
                return { err: new Error("port invalid"), type: "", value: "" };
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
        return Object.keys(this.props.listSources).sort((a, b) => a < b).map((sourceID, num) => {
            let isDisabled = !(this.props.listSources[sourceID].connectStatus);          

            return (
                <option 
                    key={`key_source_${num}_${this.props.listSources[sourceID].id}`} 
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
                        <Form.Group as={Col} className="text-left mt-1">
                            <Form.Row className="ml-1 mt-n1">
                                <Form.Check className="mt-n2" type="checkbox" onClick={this.handlerCheckbox} name="files_found" />
                                <small className="ml-1 mt-n2">файлы найдены</small>
                            </Form.Row>
                            <Form.Row className="ml-1 mt-n1">
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
                            <Form.Row className="ml-1 mt-n2">
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
                                    validator={this.handlerFieldInputValidator}
                                    onTokensUpdate={this.handlerFieldInput}
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
    handlerButtonSearch: PropTypes.func.isRequired,
};
