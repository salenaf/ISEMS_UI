import React from "react";
import { Button, Card, CardDeck, Form } from "react-bootstrap";
import PropTypes from "prop-types";

import ModalWindowAddEntity from "../../modalwindows/modalWindowAddEntity.jsx";
import { forEach } from "async";

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

        let v = (e.target.value === "all") ? null: e.target.value;

        this.setState({ chosenOrganizationID: v });

        if(e.target.value === "all"){
            this.setState({ chosenDivisionID: null });
        }
        /**
         *         this.setState({ chosenDivisionID: null });
        this.setState({ chosenOrganizationID: null });
         */
    }

    selectedDivision(e){

        console.log(`Была выбрано подразделение с ID: ${e.target.value}`);

        let v = (e.target.value === "all") ? null: e.target.value;

        this.setState({ chosenDivisionID: v });
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
                <option value="all" key={"select_division_option_none"}>добавить подразделение</option>
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


        let i = 0;
        let getTextBody = function(listEmtity, textResult, child){   
            
            console.log("func 'getTextBody'");
            console.log(listEmtity);

            if(listEmtity.legal_address){
                textResult.push(<p key={`org_l_${i}`}>Новая организация: {listEmtity.name}</p>);
                //textResult += `<p key="org_l_${i}>Новая организация: ${listEmtity.name}</p>`;
                //textResult.push(<ul key={`org_l_${i}`}>Новая организация: {listEmtity.name}</ul>);
            }

            if((typeof listEmtity.id_division !== "undefined") && (typeof listEmtity.id_source === "undefined")){
                //textResult += `<p key="div_l_${i}">${separator} Новое подразделение или филиал: ${listEmtity.name}</p>`;
                textResult.push(<li key={`div_l_${i}`}>{"\t"}Новое подразделение или филиал: {listEmtity.name}</li>);
            } 
            
            if(typeof listEmtity.id_source !== "undefined"){
                textResult.push(<li key={`sour_l_${i}`}>{"\t\t"}Новый источник: {listEmtity.source_id} {listEmtity.short_name}</li>);
            }
            /*
            if(textResult.length > 0 || child){
                if(typeof listEmtity.id_division !== "undefined"){
                    //textResult += `<p key="div_l_${i}">${separator} Новое подразделение или филиал: ${listEmtity.name}</p>`;
                    textResult.push(<li key={`div_l_${i}`}>Новое подразделение или филиал: {listEmtity.name}</li>);
                } else if(typeof listEmtity.id_source !== "undefined"){
                    textResult.push(<li key={`sour_l_${i}`}>Новый источник: ${listEmtity.source_id} ${listEmtity.short_name}</li>);
                }
            } else {
                if(typeof listEmtity.id_division !== "undefined"){
                    //textResult += `<p key="div_l_${i}">${separator} Новое подразделение или филиал: ${listEmtity.name}</p>`;
                    textResult.push(<ul key={`div_l_${i}`}>Новое подразделение или филиал: {listEmtity.name}</ul>);
                } else if(typeof listEmtity.id_source !== "undefined"){
                    textResult.push(<ul key={`sour_l_${i}`}>Новый источник: ${listEmtity.source_id} ${listEmtity.short_name}</ul>);
                }
            }
*/
            if(Array.isArray(listEmtity.division_or_branch_list_id) && listEmtity.division_or_branch_list_id.length > 0){
                    
                console.log("DIVISION");

                textResult.push(listEmtity.division_or_branch_list_id.map((item) => {
                    return getTextBody(item, [], true);
                }));
            }

            if(Array.isArray(listEmtity.source_list) && listEmtity.source_list.length > 0){
                
                console.log("SOURCES");

                textResult.push(listEmtity.source_list.map((item) => {
                    return getTextBody(item, [], true);
                }));
            }

            console.log(`length text result: ${textResult.length}, child: ${child}, (${textResult})`);
            console.log(textResult);

            return textResult;
        };
        
        return this.state.listNewEntity.map((item) => {

            //JSON.stringify(item)

            return (
                <React.Fragment key={`toast_id_${num++}`}>
                    <Card>
                        <blockquote className="text-left blockquote mb-0 card-body">
                            {getTextBody(item, [], false)}
                            <footer>
                                <br/><Button size="sm" variant="outline-danger">удалить</Button>
                            </footer>
                        </blockquote>
                    </Card>
                    <br/>
                </React.Fragment>
            );
        });
    }

    /**
 *                         <Card.Header as="h5">Добавлена новая сущность</Card.Header>
                        <Card.Body className="text-left">
                            <Card.Text>{getTextBody(item, [], false)}</Card.Text>
                            <Button size="sm" variant="outline-danger">удалить</Button>
                        </Card.Body>
 */

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