import React from "react";
import ReactDOM from "react-dom";
import { Alert, Button, Col, Row, Spinner, Nav } from "react-bootstrap";
import PropTypes from "prop-types";

import CreatingWidgets from "./createWidgets.jsx";

//import PageManagingNetworkInteractions from "./pageManagingNetworkInteractions.jsx";

import ModalWindowAddFilteringTask from "../modalwindows/modalWindowAddFilteringTask.jsx";
//import ModalWindowShowInformationTask from "../modalwindows/modalWindowShowInformationTask.jsx";
//import ModalWindowListTaskDownloadFiles from "../modalwindows/modalWindowListTaskDownloadFiles.jsx";


class CreatePageManagingNetworkInteractions extends React.Component {
    constructor(props){
        super(props);

        this.state = {
            "connectionModuleNI": this.connModuleNI.call(this),
            "widgets": {
                numConnect: this.props.listItems.widgetsInformation.numConnect,
                numDisconnect: this.props.listItems.widgetsInformation.numDisconnect,
                numProcessFiltration: this.props.listItems.widgetsInformation.numProcessFiltration,
                numProcessDownload: this.props.listItems.widgetsInformation.numProcessDownload,
                numTasksNotDownloadFiles: 0,
            },
            listSources: this.props.listItems.listSources,
            shortTaskInformation: { 
                sourceID: 0, 
                sourceName: "",
                taskID: "",
            },
            showModalWindowFiltration: false,
            showModalWindowShowTaskInformation: false,
        };

        this.userPermission=this.props.listItems.userPermissions;

        this.handlerButtonSubmitWindowFilter = this.handlerButtonSubmitWindowFilter.bind(this);
        this.handlerShowModalWindowFiltration=this.handlerShowModalWindowFiltration.bind(this);
        this.handlerCloseModalWindowFiltration=this.handlerCloseModalWindowFiltration.bind(this);
        this.handlerCloseModalWindowShowTaskInformation=this.handlerCloseModalWindowShowTaskInformation.bind(this);

        this.handlerEvents.call(this);
        this.requestEmiter.call(this);
    }

    connModuleNI(){
        return (typeof this.props.listItems !== "undefined") ? this.props.listItems.connectionModules.moduleNI: false;
    }

    requestEmiter(){
        this.props.socketIo.emit("network interaction: get list tasks to download files", { arguments: {} });
    }

    handlerEvents(){
        this.props.socketIo.on("module NI API", (data) => {
            if(data.type === "connectModuleNI"){
                if(data.options.connectionStatus){
                    this.setState({ "connectionModuleNI": true });
                    this.props.socketIo.emit("network interaction: get list tasks to download files", { arguments: {} });
                } else {
                    this.setState({ 
                        "connectionModuleNI": false,
                        "widgets": {
                            numConnect: 0,
                            numDisconnect: 0,
                            numProcessDownload: 0,
                            numProcessFiltration: 0,
                            numTasksNotDownloadFiles: 0,
                        },
                    });
                }
            }
                
            //для списка задач трафик по которым не выгружался
            if(data.type === "get list tasks files not downloaded"){
                //для виджета
                let tmpCopy = Object.assign(this.state.widgets);
                tmpCopy.numTasksNotDownloadFiles = data.options.tntf;
                this.setState({ widgets: tmpCopy });
            }
    
        });

        this.props.socketIo.on("module-ni:change sources connection", (data) => {
            let tmpCopy = Object.assign(this.state.widgets);
            tmpCopy.numConnect = data.numConnect;
            tmpCopy.numDisconnect = data.numDisconnect;
            this.setState({ widgets: tmpCopy });
        });

        //изменяем статус подключения источника для списка выбопа источника
        this.props.socketIo.on("module-ni:change status source", (data) => {
            let objCopy = Object.assign({}, this.state);
            
            console.log("received event 'module-ni:change status source'");
            console.log(data);

            for(let source in objCopy.listSources){
                if(+data.options.sourceID === +source){
                    objCopy.listSources[source].connectTime = data.options.connectTime;
                    objCopy.listSources[source].connectStatus = data.options.connectStatus;

                    this.setState(objCopy);

                    break;
                }
            }
        });
    }

    handlerShowModalWindowFiltration(){
        this.setState({ showModalWindowFiltration: true });
    }

    handlerCloseModalWindowFiltration(){
        this.setState({ showModalWindowFiltration: false });
    }

    handlerShowModalWindowShowTaskInformation(){
        this.setState({ showModalWindowShowTaskInformation: true });
    }

    handlerCloseModalWindowShowTaskInformation(){
        this.setState({ showModalWindowShowTaskInformation: false });
    }

    handlerButtonSubmitWindowFilter(objTaskInfo){
        let checkExistInputValue = () => {
            let isEmpty = true;

            done:
            for(let et in objTaskInfo.inputValue){
                for(let d in objTaskInfo.inputValue[et]){
                    if(Array.isArray(objTaskInfo.inputValue[et][d]) && objTaskInfo.inputValue[et][d].length > 0){
                        isEmpty = false;

                        break done;  
                    }
                }
            }

            return isEmpty;
        };

        //проверяем наличие хотя бы одного параметра в inputValue
        if(checkExistInputValue()){
            return;
        }

        this.props.socketIo.emit("start new filtration task", {
            actionType: "add new task",
            arguments: {
                source: objTaskInfo.source,
                dateTime: {
                    start: +(new Date(objTaskInfo.startDate)),
                    end: +(new Date(objTaskInfo.endDate)),
                },
                networkProtocol: objTaskInfo.networkProtocol,
                inputValue: objTaskInfo.inputValue,
            },
        });

        this.handlerCloseModalWindowFiltration();
    }

    showModuleConnectionError(){
        if(!this.state.connectionModuleNI){
            return (                
                <React.Fragment>
                    <br/>
                    <Alert variant="danger">
                        <Alert.Heading>Ошибка! Модуль управления сетевыми взаимодействиями.</Alert.Heading>
                        <p>
                        Отсутствует доступ к модулю. Невозможно управление сетевыми взаимодействиями
                        с удаленными источниками.
                        </p>
                    </Alert>
                    <h6>
                        Соединение&nbsp;<Spinner animation="border" variant="primary" size="sm"/>
                    </h6>
                    
                </React.Fragment>
            );
        }
    }

    isDisabledFiltering(){
        //если нет соединения с модулем сетевого взаимодействия
        if(!this.state.connectionModuleNI){
            return "disabled";
        }

        if(!this.userPermission.management_tasks_filter.element_settings.create.status){
            return "disabled";
        }      

        return (this.userPermission.management_tasks_filter.element_settings.create.status) ? "" : "disabled";
    }

    render(){
        return (
            <React.Fragment>
                <CreatingWidgets 
                    widgets={this.state.widgets} 
                    socketIo={this.props.socketIo} />
                {this.showModuleConnectionError.call(this)}
                <Row className="pt-4">
                    <Col md={12} className="text-right">
                        <Button
                            className="mx-1"
                            size="sm"
                            variant="outline-danger"                            
                            disabled={this.isDisabledFiltering.call(this)}
                            onClick={this.handlerShowModalWindowFiltration} >
                            фильтрация
                        </Button>
                        <Button 
                            disabled
                            className="mx-1"
                            size="sm"
                            variant="outline-dark" >                           
                            сетевой калькулятор
                        </Button>
                        <Button
                            disabled
                            className="mx-1"
                            size="sm"
                            variant="outline-dark" >                           
                            декодер
                        </Button>
                    </Col>
                </Row>
                <Row>
                    <Col md={12} className="mt-2">
                        <Nav justify variant="tabs">
                            <Nav.Item>
                                <Nav.Link href="/network_interaction">
                                    <small>выполняемые задачи</small>
                                </Nav.Link>
                            </Nav.Item>
                            <Nav.Item>
                                <Nav.Link href="/network_interaction_page_file_download">
                                    <small>скачивание файлов</small>
                                </Nav.Link>
                            </Nav.Item>
                            <Nav.Item>
                                <Nav.Link href="/network_interaction_page_search_tasks">
                                    <small>поиск</small>
                                </Nav.Link>
                            </Nav.Item>
                            <Nav.Item>
                                <Nav.Link eventKey="link-3">
                                    <small>статистика и аналитика</small>
                                </Nav.Link>
                            </Nav.Item>
                            <Nav.Item>
                                <Nav.Link eventKey="link-4">
                                    <small>телеметрия</small>
                                </Nav.Link>
                            </Nav.Item>
                            <Nav.Item>
                                <Nav.Link eventKey="link-5">
                                    <small>журнал событий</small>
                                </Nav.Link>
                            </Nav.Item>
                        </Nav>
                    </Col>
                </Row>
                {/*<PageManagingNetworkInteractions
                    socketIo={this.props.socketIo}
                    listSources={this.state.listSources}
                    userPermission={this.props.listItems.userPermissions}
                    connectionModuleNI={this.props.listItems.connectionModules.moduleNI} />*/}

                <ModalWindowAddFilteringTask 
                    show={this.state.showModalWindowFiltration}
                    onHide={this.handlerCloseModalWindowFiltration}
                    listSources={this.state.listSources}
                    handlerButtonSubmit={this.handlerButtonSubmitWindowFilter} />
                {/*<ModalWindowListTaskDownloadFiles 
                    show={this.state.showModalWindowListDownload}
                    onHide={this.handlerCloseModalWindowListDownload}
                    socketIo={this.props.socketIo}
                    userPermissionImport={this.userPermission.management_tasks_import.element_settings.resume.status}
                    shortTaskInfo={this.state.shortTaskInformation} />*/}
                {/*<ModalWindowShowInformationTask 
                    show={this.state.showModalWindowShowTaskInformation}
                    onHide={this.handlerCloseModalWindowShowTaskInformation}
                    socketIo={this.props.socketIo}
                    shortTaskInfo={this.state.shortTaskInformation} />*/}
            </React.Fragment>
        );
    }
}

CreatePageManagingNetworkInteractions.propTypes = {
    socketIo: PropTypes.object.isRequired,
    listItems: PropTypes.object.isRequired,
}; 

ReactDOM.render(<CreatePageManagingNetworkInteractions
    socketIo={socket}
    listItems={receivedFromServer} />, document.getElementById("header-page-content"));