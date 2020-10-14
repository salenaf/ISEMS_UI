import React from "react";
import { Button, Badge, Card, Col, Form, Row } from "react-bootstrap";
import PropTypes from "prop-types";

import ModalWindowAddEntity from "../../modal_windows/modalWindowAddEntity.jsx";

class ButtonSaveNewEntity extends React.Component {
    constructor(props){
        super(props);
    }

    render(){
        if(!this.props.showButton){
            return <div></div>;
        }

        return <Button onClick={this.props.handler} variant="outline-success" size="sm">сохранить</Button>;
    }
}

ButtonSaveNewEntity.propTypes = {
    showButton: PropTypes.bool,
    handler: PropTypes.func.isRequired,
};

export default class CreateBodyNewEntity extends React.Component {
    constructor(props){
        super(props);

        this.state = {
            addedNewEntity: false,
            showModalWindow: false,
            chosenDivisionID: null,
            chosenOrganizationID: null,
            listOrganizationName: this.createListOrganization.call(this),
            listDivisionName: this.createListDivision.call(this),
            listNewEntity: [],
        };

        this.modalWindowSettings = {
            type: "",
            name: "",
            listFieldActivity: this.getListFieldActivity.call(this),
        };


        this.handlerAddEntity = this.handlerAddEntity.bind(this);
        this.handelrButtonAdd = this.handelrButtonAdd.bind(this);
        this.closeModalWindow = this.closeModalWindow.bind(this);

        this.createNewSource = this.createNewSource.bind(this);
        this.createNewDivision = this.createNewDivision.bind(this);
        this.createNewOrganization = this.createNewOrganization.bind(this);
        
        this.createListElementDivision = this.createListElementDivision.bind(this);
        this.createListElementOrganization = this.createListElementOrganization.bind(this);
    }

    componentDidMount() {
        this.elOrg = $("#select_list_organization");
        this.elDiv = $("#select_list_division");
       
        this.elOrg.select2({
            placeholder: "добавить организацию",
            maximumInputLength: 10,
        });

        this.elDiv.select2({
            placeholder: "добавить подразделение",
            maximumInputLength: 10,
        });
    
        this.elOrg.on("change", this.selectedOrganization.bind(this));
        this.elDiv.on("change", this.selectedDivision.bind(this));
    }

    getListFieldActivity(){
        let objTmp = {};
        for(let source in this.props.listSourcesInformation){
            objTmp[this.props.listSourcesInformation[source].fieldActivity] = "";
        }

        return objTmp;
    }

    isDisabledDelete(){

        /**
        * Проверить добавилась ли новая сущность!!!
        */

        let isChecked = false;

        return (isChecked) ? "" : "disabled";
    }

    handelrButtonAdd(){
        let typeEntity = "source";

        //console.log(`organization id: ${this.state.chosenOrganizationID}, division id: ${this.state.chosenDivisionID}`);

        if(this.state.chosenOrganizationID === null){
            typeEntity = "organization";
        } else if(this.state.chosenOrganizationID !== null && this.state.chosenDivisionID === null){
            typeEntity = "division";
        }

        this.showModalWindow.call(this, typeEntity);
    }

    showModalWindow(typeEntity){

        //console.log(`Открыто модальное окно для сущности '${typeEntity}'`);

        const listTypeEntity = {
            "organization": {
                name: "организацию",
            },
            "division": {
                name: "подразделение или филиал",
            },
            "source": {
                name: "источник",
            },
        };

        this.resultBody = this.resultBody.bind(this);
        this.sendInfoNewEntity = this.sendInfoNewEntity.bind(this);

        this.modalWindowSettings.type = typeEntity;
        this.modalWindowSettings.name = listTypeEntity[typeEntity].name;
        
        this.setState({ showModalWindow: true });    
    }

    closeModalWindow(){
        this.setState({ showModalWindow: false });
    }

    selectedOrganization(e){

        //console.log(`Была выбрана организация с ID: ${e.target.value}`);

        let v = (e.target.value === "all") ? null: e.target.value;

        this.setState({ chosenOrganizationID: v });
        this.setState({ chosenDivisionID: null });
    }

    selectedDivision(e){

        //console.log(`Было выбрано подразделение с ID: ${e.target.value}`);

        let oid = null;
        let v = (e.target.value === "all") ? null: e.target.value;
        this.setState({ chosenDivisionID: v });

        for(let key in this.state.listDivisionName){   
            if(this.state.listDivisionName[key].did === v){   
                oid = this.state.listDivisionName[key].oid;
    
                break;
            }
        }                
        
        if(this.state.chosenOrganizationID === null){
            this.setState({ chosenOrganizationID: oid });
        }
    }

    createListOrganization(){
        //console.log("createListOrganization START...");

        let listTmp = {};
        for(let source in this.props.listSourcesInformation){
            listTmp[this.props.listSourcesInformation[source].organization] = this.props.listSourcesInformation[source].oid;
        }

        return listTmp;
    }

    createListDivision(){
        //console.log("createListDivision START...");

        let listTmp = {};
        for(let source in this.props.listSourcesInformation){
            listTmp[this.props.listSourcesInformation[source].division] = {
                did: this.props.listSourcesInformation[source].did,
                oid: this.props.listSourcesInformation[source].oid,
            };
        }

        return listTmp;
    }

    createListElementOrganization(){
        let selectForm = "";
        let lsi = this.state.listOrganizationName;

        let listName = Object.keys(lsi);
        listName.sort();

        let listOptions = listName.map((name) => {
            return <option value={lsi[name]} key={`select_${lsi[name]}_option`}>{name}</option>;
        });

        selectForm = <Form.Group>
            <Form.Label>Организация</Form.Label>
            <Form.Control as="select" size="sm" id="select_list_organization">
                <option value="all" key={"select_organization_option_none"}>добавить организацию</option>
                {listOptions}
            </Form.Control>
        </Form.Group>;

        return selectForm;
    }
    
    createListElementDivision(){
        let selectForm = "";       
        let lsi = {};
       
        for(let nameDivision in this.state.listDivisionName){
            let isEqual = this.state.chosenOrganizationID === this.state.listDivisionName[nameDivision].oid;
            if(isEqual || this.state.chosenOrganizationID === null || this.state.chosenOrganizationID === "all"){
                lsi[nameDivision] = this.state.listDivisionName[nameDivision].did;

                continue;
            }
        }        

        let listName = Object.keys(lsi);
        listName.sort();

        let listOptions = listName.map((name) => <option value={lsi[name]} key={`select_${lsi[name]}_option`}>{name}</option>);

        selectForm = <Form.Group>
            <Form.Label>Подразделение или филиал организации</Form.Label>
            <Form.Control as="select" size="sm" id="select_list_division">
                <option value="all" key={"select_division_option_none"}>добавить подразделение</option>
                {listOptions}
            </Form.Control>
        </Form.Group>;

        return selectForm;
    }

    handlerAddEntity(objInfo){
        switch(objInfo.windowType){
        case "organization":
            this.createNewOrganization(objInfo.options);
            
            break;

        case "division":
            this.createNewDivision(objInfo.options);

            break;

        case "source":
            this.createNewSource(objInfo.options);
        }
    }

    createNewOrganization(options){
        //console.log("func 'createNewOrganization', START...");
        //console.log(options);

        //обновляем список организаций
        let updateOrgName = this.state.listOrganizationName;
        updateOrgName[options.organizationName] = options.id;
        this.setState({ listOrganizationName: updateOrgName });
        
        let listNewEntity = this.state.listNewEntity;
        listNewEntity.push({
            id_organization: options.id,
            name: options.organizationName, // название организации (String) а-Я0-9"'.,()-
            legal_address: options.legalAddress, // юридический адрес (String) а-Я0-9.,
            field_activity: options.fieldActivity, // род деятельности (String) из заданных значений или значение по умолчанию
            division_or_branch_list_id: [] // массив с объектами типа addDivision            
        });
        this.setState({ listNewEntity: listNewEntity });

        //говорим что добавилась новая организация (отображение кнопки "Сохранить")
        this.setState({ addedNewEntity: true });
    }

    createNewDivision(options){
        console.log("func 'createNewDivision', START...");
        console.log(options);

        let isExist = false;
        let newRecord = {
            id_organization: options.parentID, // уникальный идентификатор организации (String) a-Z0-9
            id_division: options.id, // уникальный идентификатор подразделения
            name: options.divisionName, // название филиала или подразделения организации (String) а-Я0-9"'.,()-
            physical_address: options.physicalAddress, // физический адрес (String) а-Я0-9.,
            description: options.description, // дополнительное описание (String) а-Я0-9"'.()-
            source_list: [], // массив с объектами типа addSource
        };

        //обновляем список подразделений
        let updateDiviName = this.state.listDivisionName;
        updateDiviName[options.divisionName] = {
            did: options.id,
            oid: options.parentID,
        };
        this.setState({ listDivisionName: updateDiviName });

        let listNewEntity = this.state.listNewEntity;

        for(let i = 0; i < listNewEntity.length; i++){
            //ищем объект организации в listNewEntity
            if((typeof listNewEntity[i].division_or_branch_list_id !== "undefined") && (listNewEntity[i].id_organization === options.parentID)){

                console.log(`new record ${JSON.stringify(newRecord)}`);
                console.log(listNewEntity);

                listNewEntity[i].division_or_branch_list_id.push(newRecord);
                isExist = true;

                break;
            }
        }

        //если не нашли организацию просто добавляе в массив
        if(!isExist){
            listNewEntity.push(newRecord);
        }

        this.setState({ listNewEntity: listNewEntity });
        this.setState({ addedNewEntity: true });
    }

    createNewSource(options){
        //console.log("func 'createNewSource', START...");
        //console.log(options);

        let isExist = false;
        let newRecord = {
            id_division: options.parentID, // уникальный идентификатор подразделения
            id_source: options.id, // уникальный идентификатор источника
            source_id: options.sourceID, // уникальный идентификатор источника (Number) 0-9
            short_name: options.shortName, // краткое название источника (String) a-Z-_0-9
            network_settings: { // сетевые настройки для доступа к источнику
                ipaddress: options.ipAddress, // ip адрес (String) Проверка ip адреса на корректность
                port: options.port, // сетевой порт (Number) 0-9 и диапазон 1024-65565
                token_id: options.token, // идентификационный токен (String) a-Z0-9
            },
            source_settings: { // настройки источника 
                type_architecture_client_server: options.architecture, // тип клиент серверной архитектуры (источник работает в режиме клиент или сервер) (String) a-z
                transmission_telemetry: options.telemetry, // отправка телеметрии (Bool) BOOL
                maximum_number_simultaneous_filtering_processes: options.maxSimultaneousProc, // максимальное количество одновременных процессов фильтрации (Number) 0-9 и диапазон 1-10
                type_channel_layer_protocol: options.networkChannel, // тип протокола канального уровня (String) tcp/udp/any
                list_directories_with_file_network_traffic: options.directoriesNetworkTraffic, // список директорий с файлами сетевого трафика, длинна массива не должна быть 0, массив содержит сторки с символами /\_a-Z0-9
            },
            description: options.description, // дополнительное описание (String) а-Я0-9"'.,()-
        };

        let addNewSource = function(listNewEntity){
            for(let i = 0; i < listNewEntity.length; i++){
                //ищем объект организации в listNewEntity
                if(listNewEntity[i].id_division === options.parentID){
                    listNewEntity[i].source_list.push(newRecord);
                    isExist = true;
    
                    break;
                }

                if((typeof listNewEntity[i].division_or_branch_list_id !== "undefined") || Array.isArray(listNewEntity[i].division_or_branch_list_id)){
                    addNewSource(listNewEntity[i].division_or_branch_list_id);
                }
            }
        };
        let listNewEntity = this.state.listNewEntity;
        addNewSource(listNewEntity);



        //если не нашли организацию просто добавляе в массив
        if(!isExist){
            listNewEntity.push(newRecord);
        }

        this.setState({ listNewEntity: listNewEntity });
        this.setState({ addedNewEntity: true });
    }

    resultBody(){
        let i = 0;
        let getTextBody = (listEmtity, textResult, parents) => {
            if((typeof listEmtity.id_organization !== "undefined") && (typeof listEmtity.id_division === "undefined")){
                textResult.push(<div key={`org_l_${i}`}>Организация:&nbsp;<Badge variant="info">{listEmtity.name}</Badge></div>);
                parents = "organization";
            }

            if(parents === "none") {
                if((typeof listEmtity.id_division !== "undefined") && (typeof listEmtity.id_source === "undefined")){                
                    textResult.push(<div key={`div_l_${i}`}>Подразделение или филиал:&nbsp;<Badge variant="info">{listEmtity.name}</Badge></div>);
                } 
    
                if(typeof listEmtity.id_source !== "undefined"){
                    textResult.push(<div key={`sour_l_${i}`}>Источник:&nbsp;<Badge variant="info">{listEmtity.source_id} - {listEmtity.short_name}</Badge></div>);
                } 
            } else {
                if((typeof listEmtity.id_division !== "undefined") && (typeof listEmtity.id_source === "undefined")){                
                    textResult.push(<div key={`div_l_${i}`}>
                        &#8195;Подразделение или филиал:&nbsp;<Badge variant="dark">{listEmtity.name}</Badge>
                        &nbsp;<a onClick={this.delAddedElem.bind(this, listEmtity.id_division)} className="clickable_icon" href="#"><img src="./images/icons8-delete-16.png"></img></a>
                    </div>);
                } 
    
                if(parents === "organization"){
                    if(typeof listEmtity.id_source !== "undefined"){
                        textResult.push(<div key={`sour_l_${i}`}>
                            &#8195;&#8195;Источник:&nbsp;<Badge variant="dark">{listEmtity.source_id} - {listEmtity.short_name}</Badge>
                            &nbsp;<a onClick={this.delAddedElem.bind(this, listEmtity.id_source)} className="clickable_icon" href="#"><img src="./images/icons8-delete-16.png"></img></a>
                        </div>);
                    }
                } else {
                    if(typeof listEmtity.id_source !== "undefined"){
                        textResult.push(<div key={`sour_l_${i}`}>
                            &#8195;Источник:&nbsp;<Badge variant="dark">{listEmtity.source_id} - {listEmtity.short_name}</Badge>
                            &nbsp;<a onClick={this.delAddedElem.bind(this, listEmtity.id_source)} className="clickable_icon" href="#"><img src="./images/icons8-delete-16.png"></img></a>
                        </div>);
                    }
                }
                
            }                

            if(parents !== "organization") {
                parents = "division";
            }

            if(Array.isArray(listEmtity.division_or_branch_list_id) && listEmtity.division_or_branch_list_id.length > 0){
                textResult.push(listEmtity.division_or_branch_list_id.map((item) => getTextBody(item, [], parents)));
            }

            if(Array.isArray(listEmtity.source_list) && listEmtity.source_list.length > 0){
                textResult.push(listEmtity.source_list.map((item) => getTextBody(item, [], parents)));
            }

            return textResult;
        };

        let num = 0;
        return this.state.listNewEntity.map((item) => {
            let delForID = "";

            if(typeof item.id_organization !== "undefined"){
                delForID = item.id_organization;
            } else if ((typeof item.id_division !== "undefined") && (typeof item.id_source === "undefined")) {
                delForID = item.id_division;
            } else if (typeof item.id_source !== "undefined") {
                delForID = item.id_source;
            }

            return (
                <React.Fragment key={`toast_id_${num++}`}>
                    <Card>
                        <blockquote className="text-left blockquote mb-0 card-body">
                            {getTextBody(item, [], "none")}
                            <footer>
                                <br/><Button onClick={this.delAddedElem.bind(this, delForID)} size="sm" variant="outline-danger">удалить</Button>
                            </footer>
                        </blockquote>
                    </Card>
                    <br/>
                </React.Fragment>
            );
        });
    }

    delAddedElem(elemID){
        //console.log(`удалить элемент с ID ${elemID} и всех его дочерних потомков`);

        function findAndDeleteItemByID(listEntity, listOrg, listDiv, id) {
            let iterator = (obj, func) => {
                let newObj = {};
                for(let key in obj){
                    if(func(obj[key])){
                        newObj[key] = obj[key];
                    }
                }

                return newObj;
            };

            let listNameID = ["id_organization", "id_division", "id_source"];
            let searchIDAndDel = (listEntity, id) => {      
                for(let i = 0; i < listEntity.length; i++){
                    for(let name in listEntity[i]){
                        if(listNameID.includes(name)){   
                            if(listEntity[i][name] && listEntity[i][name] === id){   
                                listEntity.splice(i, 1);

                                if(name === "id_organization"){
                                    listOrg = iterator(listOrg, (value) => value !== id);
                                    listDiv = iterator(listDiv, (value) => value.oid !== id);
                                } 
                                if(name === "id_division"){
                                    listDiv = iterator(listDiv, (value) => value.did !== id);
                                }
    
                                return;
                            }   
                        }
        
                        if(Array.isArray(listEntity[i][name]) && listEntity[i][name].length > 0){
                            searchIDAndDel(listEntity[i][name], id);
                        }
                    }
                }
            };

            searchIDAndDel(listEntity, id);

            return {
                listEntity: listEntity,
                listOrganization: listOrg, 
                listDivision: listDiv,
            };
        }

        const COUNT_ORGANIZATION_NAME = Object.keys(this.state.listOrganizationName).length;
        const COUNT_DIVISION_NAME = Object.keys(this.state.listDivisionName).length;

        let modifiedObject = findAndDeleteItemByID(this.state.listNewEntity, this.state.listOrganizationName, this.state.listDivisionName, elemID);

        //изменяем тип открываемого модального окна если были изменения в объектах-списках 
        if(COUNT_ORGANIZATION_NAME > Object.keys(modifiedObject.listOrganization).length){
            this.setState({ chosenOrganizationID: null });
        }
        if(COUNT_DIVISION_NAME > Object.keys(modifiedObject.listDivision).length){
            this.setState({ chosenDivisionID: null });
        }

        this.setState({ listNewEntity: modifiedObject.listEntity });
        this.setState({ listOrganizationName: modifiedObject.listOrganization });
        this.setState({ listDivisionName: modifiedObject.listDivision });

        //убираем кнопку 'сохранить'
        if(modifiedObject.listEntity.length === 0){
            this.setState({ addedNewEntity: false });
        }

    }

    sendInfoNewEntity(){
        console.log("Отправляем информацию о новых сущностях");
    }

    render(){
        return (
            <React.Fragment>
                <br/>
                <div className="row">
                    <div className="col-md-12 text-left">
                        <Form>
                            <Row>
                                <Col>{this.createListElementOrganization()}</Col>
                                <Col>{this.createListElementDivision()}</Col>
                            </Row>
                        </Form>
                    </div>
                </div>
                <div className="row">
                    <div className="col-md-12 text-right">
                        <Button size="sm" variant="outline-primary" onClick={this.handelrButtonAdd}>добавить</Button>
                    </div>
                </div>
                <br/>
                <div className="row">
                    <div className="col-md-12">
                        {this.resultBody()}
                    </div>
                </div>
                <br/>
                <div className="row">
                    <div className="col-md-12 text-right">
                        <ButtonSaveNewEntity handler={this.sendInfoNewEntity} showButton={this.state.addedNewEntity} />
                    </div>
                </div>

                <ModalWindowAddEntity 
                    show={this.state.showModalWindow}
                    onHide={this.closeModalWindow}
                    settings={this.modalWindowSettings}
                    parentDivisionID={this.state.chosenDivisionID}
                    parentOrganizationID={this.state.chosenOrganizationID}
                    handlerAddButton={this.handlerAddEntity} />
            </React.Fragment>
        );
    }
}

CreateBodyNewEntity.propTypes ={
    listSourcesInformation: PropTypes.object.isRequired,
};