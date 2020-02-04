import React from "react";
import { Button, Card, Form } from "react-bootstrap";
import PropTypes from "prop-types";

import ModalWindowAddEntity from "../../modalwindows/modalWindowAddEntity.jsx";

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

        if(this.state.chosenOrganizationID === null){
            typeEntity = "organization";
        } else if(this.state.chosenOrganizationID !== null && this.state.chosenDivisionID === null){
            typeEntity = "division";
        }

        this.showModalWindow.call(this, typeEntity);
    }

    showModalWindow(typeEntity){

        console.log(`Открыто модальное окно для сущности '${typeEntity}'`);

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

        console.log(`Была выбрана организация с ID: ${e.target.value}`);

        this.setState({ chosenOrganizationID: e.target.value });
    }

    selectedDivision(e){

        console.log(`Была выбрано подразделение с ID: ${e.target.value}`);

        this.setState({ chosenDivisionID: e.target.value });
    }

    createListOrganization(){
        console.log("createListOrganization START...");

        let listTmp = {};
        for(let source in this.props.listSourcesInformation){
            listTmp[this.props.listSourcesInformation[source].organization] = this.props.listSourcesInformation[source].oid;
        }

        return listTmp;
    }

    createListDivision(){
        console.log("createListDivision START...");

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

        selectForm = <Form.Group onChange={this.selectedOrganization.bind(this)} controlId={"select_list_organization"}>
            <Form.Label>Организация</Form.Label>
            <Form.Control as="select" size="sm">
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
            if(this.state.chosenOrganizationID === null || this.state.chosenOrganizationID === "all"){
                lsi[nameDivision] = this.state.listDivisionName[nameDivision].did;

                continue;
            }

            if(this.state.chosenOrganizationID === this.state.listDivisionName[nameDivision].oid){
                lsi[nameDivision] = this.state.listDivisionName[nameDivision].did;
            }
        }        

        let listName = Object.keys(lsi);
        listName.sort();

        let listOptions = listName.map((name) => <option value={lsi[name]} key={`select_${lsi[name]}_option`}>{name}</option>);

        selectForm = <Form.Group onChange={this.selectedDivision.bind(this)} controlId={"select_list_division"}>
            <Form.Label>Подразделение или филиал организации</Form.Label>
            <Form.Control as="select" size="sm">
                <option value={null} key={"select_division_option_none"}>добавить подразделение</option>
                {listOptions}
            </Form.Control>
        </Form.Group>;

        return selectForm;
    }

    handlerAddEntity(objInfo){
        console.log("func 'handlerAddButton', START...");
        console.log(objInfo);

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

        console.log("func 'handlerAddButton', END...");
    }

    createNewOrganization(options){
        console.log("func 'createNewOrganization', START...");
        console.log(options);

        /**
  windowType: this.props.settings.type,
                options: {
                    id: helpers.tokenRand(),
                    organizationName: settings.organizationSettings.organizationName.value,
                    legalAddress: settings.organizationSettings.legalAddress.value,
                    fieldActivity: settings.organizationSettings.fieldActivity.value,
                }, 
 */

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

        //обновляем список организаций
        let updateDiviName = this.state.listDivisionName;
        updateDiviName[options.divisionName] = {
            did: options.id,
            oid: options.parentID,
        };
        this.setState({ listDivisionName: updateDiviName });

        let listNewEntity = this.state.listNewEntity;

        for(let i = 0; i < listNewEntity.length; i++){

            console.log(`id organization: ${listNewEntity[i].id_organization} === ${options.parentID} (parent ID)`);

            //ищем объект организации в listNewEntity
            if(listNewEntity[i].id_organization === options.parentID){
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
        console.log("func 'createNewSource', START...");
        console.log(options);

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

        let listNewEntity = this.state.listNewEntity;
        for(let i = 0; i < listNewEntity.length; i++){

            console.log(`id division: ${listNewEntity[i].id_division} === ${options.parentID} (parent ID)`);

            //ищем объект организации в listNewEntity
            if(listNewEntity[i].id_division === options.parentID){
                listNewEntity[i].source_list.push(newRecord);
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

    resultBody(){
        /*
    Examlpe object:

        "Описание организации": {
            name: "", // название организации (String) а-Я0-9"'.,()-
            legal_address: "", // юридический адрес (String) а-Я0-9.,
            field_activity: "", // род деятельности (String) из заданных значений или значение по умолчанию
            division_or_branch_list_id: [] // массив с объектами типа addDivision
        }

        "Описание филиала или подразделения организации": {
            id_organization: "", // уникальный идентификатор организации (String) a-Z0-9
            name: "", // название филиала или подразделения организации (String) а-Я0-9"'.,()-
            physical_address: "", // физический адрес (String) а-Я0-9.,
            description: "", // дополнительное описание (String) а-Я0-9"'.()-
            source_list: [], // массив с объектами типа addSource
        }

        "Описание источника обработки файлов, установленного в филиала или подразделения организации": {
            id_division: "", // уникальный идентификатор филиала или подразделения организации (String) a-Z0-9
            source_id: "", // уникальный идентификатор источника (Number) 0-9
            short_name: "", // краткое название источника (String) a-Z-_0-9
            network_settings: { // сетевые настройки для доступа к источнику
                ipaddress: "", // ip адрес (String) Проверка ip адреса на корректность
                port: 0, // сетевой порт (Number) 0-9 и диапазон 1024-65565
                token_id: "", // идентификационный токен (String) a-Z0-9
            },
            source_settings: { // настройки источника 
                type_architecture_client_server: "", // тип клиент серверной архитектуры (источник работает в режиме клиент или сервер) (String) a-z
                transmission_telemetry: false, // отправка телеметрии (Bool) BOOL
                maximum_number_simultaneous_filtering_processes: 0, // максимальное количество одновременных процессов фильтрации (Number) 0-9 и диапазон 1-10
                type_channel_layer_protocol: "", // тип протокола канального уровня (String) tcp/udp/any
                list_directories_with_file_network_traffic: [], // список директорий с файлами сетевого трафика, длинна массива не должна быть 0, массив
                 содержит сторки с символами /\_a-Z0-9
            },
            description: "", // дополнительное описание (String) а-Я0-9"'.,()-
        }

    */

        let num = 0;
        let listNewEntity = this.state.listNewEntity.map((item) => {
            return (
                <React.Fragment key={`toast_id_${num++}`}>
                    <Card>
                        <Card.Header as="h5">Featured</Card.Header>
                        <Card.Body className="text-left">
                            <Card.Title>Special title treatment</Card.Title>
                            <Card.Text>
                                {JSON.stringify(item)}
                            </Card.Text>
                            <Button size="sm" variant="outline-danger">удалить</Button>
                        </Card.Body>
                    </Card>
                    <br/>
                </React.Fragment>
            );
        });

        return listNewEntity;
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
                            {this.createListElementOrganization()}
                            {this.createListElementDivision()}
                        </Form>
                    </div>
                </div>
                <div className="row">
                    <div className="col-md-12 text-right">
                        <Button size="sm" variant="outline-primary" onClick={this.handelrButtonAdd}>добавить</Button>
                    </div>
                </div>
                <div className="row">
                    <br/>
                    {this.resultBody()}
                    <br/>
                </div>
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