import React from "react";
import ReactDOM from "react-dom";
import { Button, Tab, Tabs } from "react-bootstrap";
import PropTypes from "prop-types";

import CreateTableSources from "./createTableSources.jsx";
import CreateTableDivision from "./createTableDivision.jsx";
import CreateBodyNewEntity from "./createBodyNewEntity.jsx";
import ModalWindowSourceInfo from "../../modalwindows/modalWindowSourceInfo.jsx";
import ModalWindowChangeOrganizationOrSource from "../../modalwindows/modalWindowChangeOrganizationOrSource.jsx";
import { ModalWindowConfirmMessage } from "../../modalwindows/modalWindowConfirmMessage.jsx";

class CreatePageOrganizationAndSources extends React.Component {
    constructor(props){
        super(props);

        this.state = {
            "modalWindowSourceInfo": false,
            "modalWindowSourceDel": false,
            "modalWindowChangeOrganizationOrSource": false,
            "checkboxMarkedSourceDel": this.createStateCheckboxMarkedSourceDel.call(this),
        };

        this.modalWindowSourceInfoSettings = {
            id: 0,
            typeElem: "",
        };

        this.listSourceDelete = [];

        this.showModalWindowSourceInfo = this.showModalWindowSourceInfo.bind(this);
        this.closeModalWindowSourceInfo = this.closeModalWindowSourceInfo.bind(this);
        this.showModalWindowSourceDel = this.showModalWindowSourceDel.bind(this);
        this.closeModalWindowSourceDel = this.closeModalWindowSourceDel.bind(this);
        this.showModalWindowChangeOrganizationOrSource = this.showModalWindowChangeOrganizationOrSource.bind(this);
        this.closeModalWindowChangeOrganizationOrSource = this.closeModalWindowChangeOrganizationOrSource.bind(this);

        this.changeCheckboxMarkedSourceDel = this.changeCheckboxMarkedSourceDel.bind(this);
        this.handlerSourceDelete = this.handlerSourceDelete.bind(this);
    }

    createStateCheckboxMarkedSourceDel(){
        let listSource = Object.keys(this.props.listSourcesInformation);

        let list = {};
        listSource.forEach(id => {
            list[id] = {
                checked: false,
            };
        });

        return list;
    }

    showModalWindowSourceInfo(sourceID){
        this.modalWindowSourceInfoSettings.id = sourceID;

        /**
         * отправить через socketIo запрос на получение
         * полной информации об источнике 
         */

        this.setState({"modalWindowSourceInfo": true});
    }

    closeModalWindowSourceInfo(){
        this.setState({"modalWindowSourceInfo": false});
    }

    showModalWindowChangeOrganizationOrSource(sourceID, typeElem){
        this.modalWindowSourceInfoSettings.id = sourceID;
        this.modalWindowSourceInfoSettings.typeElem = typeElem;

        this.setState({"modalWindowChangeOrganizationOrSource": true});
    }

    closeModalWindowChangeOrganizationOrSource(){
        this.setState({"modalWindowChangeOrganizationOrSource": false});
    }

    showModalWindowSourceDel(){
        this.listSourceDelete = [];
        for(let id in this.state.checkboxMarkedSourceDel){
            if(this.state.checkboxMarkedSourceDel[id].checked){
                this.listSourceDelete.push(id);
            }
        }

        if(this.listSourceDelete.length === 0) return;

        this.setState({"modalWindowSourceDel": true});
    }

    closeModalWindowSourceDel(){
        this.setState({"modalWindowSourceDel": false});
    }

    changeCheckboxMarkedSourceDel(sourceID){
        let stateCopy = Object.assign({}, this.state);
        stateCopy.checkboxMarkedSourceDel[sourceID].checked = !this.state.checkboxMarkedSourceDel[sourceID].checked;

        this.setState({ stateCopy });
    }

    handlerSourceDelete(){
        console.log(`УДАЛЯЕМ ИСТОЧНИКИ № ${this.listSourceDelete}`);
    }

    isDisabledDelete(typeButton){

        /**
        * Еще проверить групповую политику пользователя
        */

        let isChecked = false;
        let settings = {
            "sourceDel": this.state.checkboxMarkedSourceDel,
        };

        for(let id in settings[typeButton]){
            if(settings[typeButton][id].checked){
                isChecked = true;

                break;
            }
        }

        return (isChecked) ? "" : "disabled";
    }

    render(){
        return (
            <React.Fragment>
                <Tabs defaultActiveKey="sources" id="uncontrolled-tab-example">
                    <Tab eventKey="sources" title="Источники">
                        <br/>
                        <div className="row">
                            <div className="col-md-9 text-left">Всего источников: {Object.keys(this.state.checkboxMarkedSourceDel).length}</div>
                            <div className="col-md-3 text-right">
                                <Button 
                                    variant="outline-danger" 
                                    onClick={this.showModalWindowSourceDel}
                                    disabled={this.isDisabledDelete.call(this, "sourceDel")}
                                    size="sm">удалить</Button>
                            </div>
                        </div>
                        <CreateTableSources 
                            changeCheckboxMarked={this.changeCheckboxMarkedSourceDel}
                            handlerShowInfoWindow={this.showModalWindowSourceInfo}
                            handlerShowChangeInfo={this.showModalWindowChangeOrganizationOrSource}
                            listSourcesInformation={this.props.listSourcesInformation}/>
                    </Tab>
                    <Tab eventKey="division" title="Подразделения">
                        <CreateTableDivision listDivisionInformation={this.props.listDivisionInformation}/>
                    </Tab>
                    <Tab eventKey="organization" title="Организации">
                        <div>Organization</div>
                    </Tab>
                    <Tab eventKey="addElement" title="Новая сущность">
                        
                        {/** Затенять и делать не активным, при запрете группе добавлять новые сущности */}
                        
                        <CreateBodyNewEntity listSourcesInformation={this.props.listSourcesInformation}/>
                    </Tab>
                </Tabs>
                <ModalWindowSourceInfo 
                    show={this.state.modalWindowSourceInfo}
                    onHide={this.closeModalWindowSourceInfo}
                    settings={this.modalWindowSourceInfoSettings} 
                    sourceInfoForTest={this.props.listSourcesFullInformation} />
                <ModalWindowChangeOrganizationOrSource                     
                    show={this.state.modalWindowChangeOrganizationOrSource}
                    onHide={this.closeModalWindowChangeOrganizationOrSource}
                    settings={this.modalWindowSourceInfoSettings} />
                <ModalWindowConfirmMessage 
                    show={this.state.modalWindowSourceDel}
                    onHide={this.closeModalWindowSourceDel}
                    msgBody={`Вы действительно хотите удалить ${(this.listSourceDelete.length > 1) ? "источники с номерами": "источник с номером"} ${this.listSourceDelete}`}
                    msgTitle={"Удаление"}
                    nameDel={this.listSourceDelete.join()}
                    handlerConfirm={this.handlerSourceDelete}
                />
            </React.Fragment>
        );
    }
}

CreatePageOrganizationAndSources.propTypes ={
    listSourcesFullInformation: PropTypes.object,
    listSourcesInformation: PropTypes.object.isRequired,
    listDivisionInformation: PropTypes.array.isRequired,
};

let listSourcesInformation = {
    100: {
        "sid": "ffeo0393f94h8884h494g4g",
        "did": "dnjdjdnuw82hd8h882h82h8h",
        "oid": "cnw9w9dj93d8383d8h38d83f4",
        "shortName": "RosAtom COD 1",
        "dateRegister": "2019-08-13 14:39:08",
        "fieldActivity": "атомная промышленность",
        "division": "Центр обработки данных №1",
        "organization": "Государственная корпорация атомной энергии Росатом",
        "versionApp": "v1.4.4",
        "releaseApp": "12.12.2019",
    },
    102: {
        "sid": "bmfomr94jbv4nrb949gh94g994",
        "did": "vm93j9939f9933993uf9rrrrr",
        "oid": "cnw9w9dj93d8383d8h38d83f4",
        "shortName": "RosAtom COD 2",
        "dateRegister": "2020-01-13 10:13:00",
        "fieldActivity": "атомная промышленность",
        "division": "Центр обработки данных №2",
        "organization": "Государственная корпорация атомной энергии Росатом",
        "versionApp": "v1.4.4",
        "releaseApp": "12.12.2019",
    },
    106: {
        "sid": "nx0j29jf993h88v84g84gf8asa",
        "did": "vievieivihf83h38f838hfh3f8",
        "oid": "cne8h8h828882yfd337fg3g838",
        "shortName": "RosCosmos COD 1",
        "fieldActivity": "космическая промышленность",
        "dateRegister": "2019-11-12 01:35:18",
        "division": "Центр обработки данных №2",
        "organization": "Государственная корпорация по космической деятельности \"РОСКОСМОС\"",
        "versionApp": "v1.4.4",
        "releaseApp": "12.12.2019",
    },
    103: {
        "sid": "xjn99393ru93ru9439r93ur933",
        "did": "nwc99983883h8hrf38fh83f383",
        "oid": "cnw89h8dh38h8h38fhd838f83",
        "shortName": "UMCHS Belgorod",
        "dateRegister": "2019-12-16 18:03:20",
        "fieldActivity": "органы безопасности",
        "division": "Управление МЧС России по Белгородской области",
        "organization": "МЧС России",
        "versionApp": "v1.4.4",
        "releaseApp": "12.12.2019",
    },
    104: {
        "sid": "n9j0j349849ur8u8488384833",
        "did": "xaja9ja9j9j93j380aj016d25",
        "oid": "cnw89h8dh38h8h38fhd838f83",
        "shortName": "UMCHS Tambov",
        "dateRegister": "2019-08-13 16:19:59",
        "fieldActivity": "органы безопасности",
        "division": "Управление МЧС России по Тамбовской области",
        "organization": "МЧС России",
        "versionApp": "v1.4.4",
        "releaseApp": "12.12.2019",
    },
    1015: {
        "sid": "vm0pc0fff3933030jr0i34344",
        "did": "dwj289j38838r8r8838r3r393",
        "oid": "dj929d29euu93438r84r49392",
        "shortName": "DZO Briansk",
        "dateRegister": "2019-02-30 07:49:48",
        "fieldActivity": "государственные органы",
        "division": "Департамент здравоохранения Брянской области",
        "organization": "Департамент здравоохранения",
        "versionApp": "v1.4.4",
        "releaseApp": "12.12.2019",
    },
};

let listSourcesFullInformation = {
    100: {
        "id": "ffeo0393f94h8884h494g4g",
        "shortName": "RosAtom COD 1",
        "dateRegister": "2019-08-13 14:39:08",
        "dateChange": "2020-01-02 10:45:43",
        "description": "какие то замечания или описание об источнике...",
        "division": {
            "name": "Центр обработки данных №1",
            "dateRegister": "2019-08-12 11:32:08",
            "dateChange": "2020-01-03 11:45:43",
            "physicalAddress": "г.Москва, ул. Удальцова, д.3",
            "description": "какие то замечания или описание по подразделению...",
            "countSources": 1,
        },
        "organization": {
            "name": "Государственная корпорация атомной энергии Росатом",
            "dateRegister": "2019-08-12 11:32:08",
            "dateChange": "2020-01-03 03:15:43",
            "fieldActivity": "атомная промышленность",
            "legalAddress": "123482 г. Москва, Дмитровское шоссе, д. 67, к. 3",
            "countDivision": 1,
        },
        "networkSettings": { 
            "ip": "12.63.55.9", 
            "port": 13113, 
            "tokenID": "ffffoeo39fj94j949tj949j94j9tj4t", 
        },
        "sourceSettings": {
            "architecture": "client",
            "telemetry": false,
            "maxNumFilter": 3,
            "typeChannelLayerProto": "ip",
            "listDirWithFileNetworkTraffic": ["/__CURRENT_DISK_1","/__CURRENT_DISK_2", "/__CURRENT_DISK_3"],
        },
        "infoAboutApp": {
            "versionApp": "v1.4.4",
            "releaseApp": "12.12.2019",
        },
    },
    102: {
        "id": "bmfomr94jbv4nrb949gh94g994",
        "shortName": "RosAtom COD 2",
        "dateRegister": "2020-01-13 10:13:00",
        "dateChange": "2020-01-02 10:45:43",
        "description": "какие то замечания или описание об источнике...",
        "division": {
            "name": "Центр обработки данных №2",
            "dateRegister": "2019-08-12 11:32:08",
            "dateChange": "2020-01-03 11:45:43",
            "physicalAddress": "г.Москва, ул. Щербаковская, д.13",
            "description": "какие то замечания или описание по подразделению...",
            "countSources": 3,
        },
        "organization": {
            "name": "Государственная корпорация атомной энергии Росатом",
            "dateRegister": "2019-08-12 11:32:08",
            "dateChange": "2020-01-03 03:15:43",
            "fieldActivity": "атомная промышленность",
            "legalAddress": "123482 г. Москва, Дмитровское шоссе, д. 67, к. 3",
            "countDivision": 1,
        },
        "networkSettings": { 
            "ip": "235.163.50.19", 
            "port": 13113, 
            "tokenID": "vndoonvnnnd2dnsnd92enbbr3", 
        },
        "sourceSettings": {
            "architecture": "server",
            "telemetry": false,
            "maxNumFilter": 4,
            "typeChannelLayerProto": "ip",
            "listDirWithFileNetworkTraffic": ["/__CURRENT_DISK_1","/__CURRENT_DISK_2", "/__CURRENT_DISK_3"],
        },
        "infoAboutApp": {
            "versionApp": "v1.4.4",
            "releaseApp": "12.12.2019",
        },
    },
    106: {
        "id": "nx0j29jf993h88v84g84gf8asa",
        "shortName": "RosCosmos COD 1",
        "dateRegister": "2019-01-12 13:13:13",
        "dateChange": "2020-01-01 08:15:43",
        "description": "какие то замечания или описание об источнике...",
        "division": {
            "name": "Центр обработки данных №1",
            "dateRegister": "2019-08-12 11:32:08",
            "dateChange": "2020-01-03 11:45:43",
            "physicalAddress": "г.Москва, ул. Удальцова, д.3",
            "description": "какие то замечания или описание по подразделению...",
            "countSources": 1,
        },
        "organization": {
            "name": "Государственная корпорация по космической деятельности \"РОСКОСМОС\"",
            "dateRegister": "2019-08-12 11:32:08",
            "dateChange": "2020-01-03 03:15:43",
            "fieldActivity": "космическая промышленность",
            "legalAddress": "123482 г. Москва, Ленинский пр., д. 100, к. 1",
            "countDivision": 2, 
        },
        "networkSettings": { 
            "ip": "89.13.115.129", 
            "port": 13113, 
            "tokenID": "fckf0k034r0f949h93h3tt4", 
        },
        "sourceSettings": {
            "architecture": "client",
            "telemetry": false,
            "maxNumFilter": 4,
            "typeChannelLayerProto": "ip",
            "listDirWithFileNetworkTraffic": ["/__CURRENT_DISK_1","/__CURRENT_DISK_2", "/__CURRENT_DISK_3"],
        },
        "infoAboutApp": {
            "versionApp": "v1.4.4",
            "releaseApp": "12.12.2019",
        },
    },
    103: {
        "id": "xjn99393ru93ru9439r93ur933",
        "shortName": "UMCHS Belgorod",
        "dateRegister": "2019-12-16 18:03:20",
        "dateChange": "2020-01-01 08:15:43",
        "description": "какие то замечания или описание об источнике...",
        "division": {
            "name": "Управление МЧС России по Белгородской области",
            "dateRegister": "2019-08-12 11:32:08",
            "dateChange": "2020-01-03 11:45:43",
            "physicalAddress": "г.Белгород, ул. Ленина, д.3",
            "description": "какие то замечания или описание по подразделению...",
            "countSources": 2,
        },
        "organization": {
            "name": "МЧС России",
            "dateRegister": "2019-08-12 11:32:08",
            "dateChange": "2020-01-03 03:15:43",
            "fieldActivity": "органы безопасности",
            "legalAddress": "123482 г. Москва, пр. Мира, д. 4, к. 1",
            "countDivision": 3,
        },
        "networkSettings": { 
            "ip": "32.56.4.44", 
            "port": 13113, 
            "tokenID": "jfj29ewj9u93r3rfvefefr3r33", 
        },
        "sourceSettings": {
            "architecture": "client",
            "telemetry": false,
            "maxNumFilter": 4,
            "typeChannelLayerProto": "ip",
            "listDirWithFileNetworkTraffic": ["/__folder_1","/__folder_2", "/__folder_3"],
        },
        "infoAboutApp": {
            "versionApp": "v1.4.4",
            "releaseApp": "12.12.2019",
        },
    },
    104: {
        "id": "n9j0j349849ur8u8488384833",
        "shortName": "UMCHS Tambov",
        "dateRegister": "2019-08-13 16:19:59",
        "dateChange": "2020-01-01 08:15:43",
        "description": "какие то замечания или описание об источнике...",
        "division": {
            "name": "Управление МЧС России по Тамбовской области",
            "dateRegister": "2019-08-12 11:32:08",
            "dateChange": "2020-01-03 11:45:43",
            "physicalAddress": "г.Тамбов, ул. 1-ого Мая, д.13",
            "description": "какие то замечания или описание по подразделению...",
            "countSources": 1,
        },
        "organization": {
            "name": "МЧС России",
            "dateRegister": "2019-08-12 11:32:08",
            "dateChange": "2020-01-03 03:15:43",
            "fieldActivity": "органы безопасности",
            "legalAddress": "123482 г. Москва, пр. Мира, д. 4, к. 1",
            "countDivision": 1,
        },
        "networkSettings": { 
            "ip": "56.123.3.11", 
            "port": 13113, 
            "tokenID": "cmoocw00f39f39f93320j0f2", 
        },
        "sourceSettings": {
            "architecture": "client",
            "telemetry": false,
            "maxNumFilter": 4,
            "typeChannelLayerProto": "ip",
            "listDirWithFileNetworkTraffic": ["/__folder_1","/__folder_2", "/__folder_3"],
        },
        "infoAboutApp": {
            "versionApp": "v1.4.4",
            "releaseApp": "12.12.2019",
        },
    },
    1015: {
        "id": "vm0pc0fff3933030jr0i34344",
        "shortName": "DZO Briansk",
        "dateRegister": "2019-02-30 07:49:48",
        "dateChange": "2020-01-01 08:15:43",
        "description": "какие то замечания или описание об источнике...",
        "division": {
            "name": "Департамент здравоохранения Брянской области",
            "dateRegister": "2019-08-12 11:32:08",
            "dateChange": "2020-01-03 11:45:43",
            "physicalAddress": "г.Брянск, ул. Возраждения, д.20",
            "description": "какие то замечания или описание по подразделению...",
            "countSources": 2,
        },
        "organization": {
            "name": "Департамент здравоохранения",
            "dateRegister": "2019-08-12 11:32:08",
            "dateChange": "2020-01-03 03:15:43",
            "fieldActivity": "государственные органы",
            "legalAddress": "123482 г. Москва, ул. Зорге, д. 14",
            "countDivision": 2, 
        },
        "networkSettings": { 
            "ip": "56.123.3.11", 
            "port": 13113, 
            "tokenID": "cmoocw00f39f39f93320j0f2", 
        },
        "sourceSettings": {
            "architecture": "client",
            "telemetry": false,
            "maxNumFilter": 4,
            "typeChannelLayerProto": "ip",
            "listDirWithFileNetworkTraffic": ["/__custom_1","/__custom_2", "/__custom_3"],
        },
        "infoAboutApp": {
            "versionApp": "v1.4.4",
            "releaseApp": "12.12.2019",
        },
    },
};

let listDivisionInformation = [
    {
        "id": "jcj992h9e92h9hf948hf94",
        "divisionName": "Департамент здравоохранения Брянской области",
        "organization": "Департамент здравоохранения",
        "dateRegister": "2019-04-13 11:49:24",
        "countSources": 2
    },
    {
        "id": "cn983jd939h84f849fh3rr3",
        "divisionName": "Управление МЧС России по Тамбовской области",
        "organization": "МЧС России",
        "dateRegister": "2019-10-23 11:08:24",
        "countSources": 1
    },
    {
        "id": "cn38rr9u39u39499349uf9",
        "divisionName": "Управление МЧС России по Белгородской области",
        "organization": "МЧС России",
        "dateRegister": "2019-05-14 09:43:21",
        "countSources": 1
    },
    {
        "id": "m09j92e93u8e3u39ur99uf9",
        "divisionName": "Центр обработки данных №2",
        "organization": "Государственная корпорация по космической деятельности \"РОСКОСМОС\"",
        "dateRegister": "2019-05-14 19:23:42",
        "countSources": 1
    },
    {
        "id": "m9wjd9j9d29934949r9d9w",
        "divisionName": "Центр обработки данных №1",
        "organization": "Государственная корпорация атомной энергии Росатом",
        "dateRegister": "2020-01-14 14:23:42",
        "countSources": 1
    },
    {
        "id": "ffej9jf39j03i0ir40i3434",
        "divisionName": "Центр обработки данных №2",
        "organization": "Государственная корпорация атомной энергии Росатом",
        "dateRegister": "2020-01-14 14:23:42",
        "countSources": 1
    },
];

ReactDOM.render(<CreatePageOrganizationAndSources 
    listSourcesFullInformation={listSourcesFullInformation}
    listSourcesInformation={listSourcesInformation}
    listDivisionInformation={listDivisionInformation} />, document.getElementById("main-page-content"));