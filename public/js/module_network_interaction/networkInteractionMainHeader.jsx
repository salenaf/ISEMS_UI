import React from "react";
import ReactDOM from "react-dom";
import { Button, Col, Row } from "react-bootstrap";
import { Alert } from "material-ui-lab";
import { Tab, Tabs, LinearProgress } from "@material-ui/core";
import PropTypes from "prop-types";

import CreatingWidgets from "./createWidgets.jsx";
import ModalWindowLanCalc from "../modal_windows/modalWindowLanCalc.jsx";
import ModalWindowEncodeDecoder from "../modal_windows/modalWindowEncodeDecoder.jsx";
import ModalWindowAddFilteringTask from "../modal_windows/modalWindowAddFilteringTask.jsx";
import ModalWindowShowInformationConnectionStatusSources from "../modal_windows/modalWindowShowInformationConnectionStatusSources.jsx";

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
                numUnresolvedTask: 0,
            },
            listSources: this.props.listItems.listSources,
            shortTaskInformation: { 
                sourceID: 0, 
                sourceName: "",
                taskID: "",
            },
            showModalWindowLanCalc: false,
            showModalWindowFiltration: false,
            showModalWindowEncodeDecoder: false,
            showModalWindowShowTaskInformation: false,
            showModalWindowInfoConnectStatusSources: false,
        };

        this.menuItem = {
            "/network_interaction": { "num": 0, "label": "прогресс" },
            "/network_interaction_page_file_download": { "num": 1, "label": "выгрузка файлов" },
            "/network_interaction_page_search_tasks": { "num": 2, "label": "поиск" },
            "/network_interaction_page_statistics_and_analytics": { "num": 3, "label": "аналитика" },
            "/network_interaction_page_telemetry": { "num": 4, "label": "телеметрия" },
            "/network_interaction_page_notification_log": { "num": 5, "label": "журнал событий" },
        };

        this.userPermission = this.props.listItems.userPermissions;

        this.handlerShowModalWindowLanCalc = this.handlerShowModalWindowLanCalc.bind(this);
        this.handlerCloseModalWindowLanCalc = this.handlerCloseModalWindowLanCalc.bind(this);
        this.handlerButtonSubmitWindowFilter = this.handlerButtonSubmitWindowFilter.bind(this);
        this.handlerShowModalWindowFiltration = this.handlerShowModalWindowFiltration.bind(this);
        this.handlerCloseModalWindowFiltration = this.handlerCloseModalWindowFiltration.bind(this);
        this.handlerShowModalWindowEncodeDecoder = this.handlerShowModalWindowEncodeDecoder.bind(this);
        this.handlerCloseModalWindowEncodeDecoder = this.handlerCloseModalWindowEncodeDecoder.bind(this);
        this.handlerCloseModalWindowShowTaskInformation = this.handlerCloseModalWindowShowTaskInformation.bind(this);
        this.handlerShowModalWindowInfoConnectStatusSources = this.handlerShowModalWindowInfoConnectStatusSources.bind(this);
        this.handlerCloseModalWindowInfoConnectStatusSources = this.handlerCloseModalWindowInfoConnectStatusSources.bind(this);

        this.handlerEvents.call(this);
        this.requestEmitter.call(this);
    }

    connModuleNI(){
        return (typeof this.props.listItems !== "undefined") ? this.props.listItems.connectionModules.moduleNI: false;
    }

    requestEmitter(){
        if(!this.state.connectionModuleNI){
            return;
        }

        if(window.location.pathname !== "/network_interaction_page_file_download"){
            this.props.socketIo.emit("network interaction: get list tasks to download files", { arguments: { forWidgets: true } });            
        }

        if(window.location.pathname !== "/network_interaction_page_statistics_and_analytics"){
            this.props.socketIo.emit("network interaction: get list of unresolved tasks", { arguments: { forWidgets: true } });               
        }
    }

    handlerEvents(){
        this.props.socketIo.on("module NI API", (data) => {
            if(data.type === "connectModuleNI"){
                if(data.options.connectionStatus){
                    this.setState({ "connectionModuleNI": true });

                    location.reload();
                } else {
                    if(!this.state.connectionModuleNI){
                        return;
                    }

                    let objClone = Object.assign({}, this.state.listSources);
                    for(let sid in objClone){
                        objClone[sid].connectStatus = false;
                    }

                    this.setState({ 
                        "connectionModuleNI": false,
                        "widgets": {
                            numConnect: 0,
                            numDisconnect: 0,
                            numProcessDownload: 0,
                            numProcessFiltration: 0,
                            numTasksNotDownloadFiles: 0,
                            numUnresolvedTask: 0,
                        },
                        "listSources": objClone,
                    });
                }
            }
                
            //для списка задач трафик по которым не выгружался
            if(data.type === "get list tasks files not downloaded for widget" || data.type === "get list tasks files not downloaded"){
                //для виджета
                let tmpCopy = Object.assign(this.state.widgets);
                tmpCopy.numTasksNotDownloadFiles = data.options.tntf;
                this.setState({ widgets: tmpCopy });
            }
    
            //для списка задач не отмеченных пользователем как завершеные
            if(data.type === "get list unresolved task for widget" || data.type === "get list unresolved task"){
                //для виджета
                let tmpCopy = Object.assign(this.state.widgets);
                tmpCopy.numUnresolvedTask = data.options.tntf;
                this.setState({ widgets: tmpCopy });
            }
        });

        this.props.socketIo.on("module-ni:change sources connection", (data) => {
            let tmpCopy = Object.assign(this.state.widgets);
            tmpCopy.numConnect = data.numConnect;
            tmpCopy.numDisconnect = data.numDisconnect;
            this.setState({ widgets: tmpCopy });
        });

        //изменяем статус подключения источника для списка выбора источника
        this.props.socketIo.on("module-ni:change status source", (data) => {
            let objCopy = Object.assign({}, this.state);

            for(let source in objCopy.listSources){
                if(+data.options.sourceID === +source){
                    objCopy.listSources[source].appVersion = data.options.appVersion;
                    objCopy.listSources[source].connectTime = data.options.connectTime;
                    objCopy.listSources[source].connectStatus = data.options.connectStatus;
                    objCopy.listSources[source].appReleaseDate = data.options.appReleaseDate;

                    this.setState(objCopy);

                    break;
                }
            }
        });

        //добавляем версию и дату программного обеспечения исчтоника
        this.props.socketIo.on("module-ni:send version app", (data) => {
            let objCopy = Object.assign({}, this.state);

            for(let source in objCopy.listSources){
                if(+data.options.sourceID === +source){
                    objCopy.listSources[source].appVersion = data.options.appVersion,
                    objCopy.listSources[source].appReleaseDate = data.options.appReleaseDate,

                    this.setState(objCopy);

                    break;
                }
            }
        });
    }

    handlerShowModalWindowFiltration(){
        this.props.socketIo.emit("give me new short source list", {});

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

    handlerShowModalWindowLanCalc(){
        this.setState({ showModalWindowLanCalc: true });        
    }

    handlerCloseModalWindowLanCalc(){
        this.setState({ showModalWindowLanCalc: false });
    }

    handlerShowModalWindowEncodeDecoder(){
        this.setState({ showModalWindowEncodeDecoder: true });
    }

    handlerCloseModalWindowEncodeDecoder(){
        this.setState({ showModalWindowEncodeDecoder: false });
    }

    handlerShowModalWindowInfoConnectStatusSources(){
        this.setState({ showModalWindowInfoConnectStatusSources: true });        
    }

    handlerCloseModalWindowInfoConnectStatusSources(){
        this.setState({ showModalWindowInfoConnectStatusSources: false });
    }

    handlerButtonSubmitWindowFilter(objTaskInfo){
        /*let checkExistInputValue = () => {
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
        }*/

        this.props.socketIo.emit("network interaction: start new filtration task", {
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

        //this.handlerCloseModalWindowFiltration();
    }

    showModuleConnectionError(){
        if(!this.state.connectionModuleNI){
            return (                
                <React.Fragment>
                    <Row className="mt-2">
                        <Col md={12}>
                            <Alert variant="filled" severity="error">
                                <strong>Ошибка!</strong> Отсутствует доступ к модулю управления сетевыми взаимодействиями. Пытаемся установить соединение...
                            </Alert>
                        </Col>
                    </Row>
                    <Row>
                        <Col md={12}>
                            <LinearProgress color="secondary" />
                        </Col>
                    </Row>                   
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

    createMenuItems(){
        let list = [];
        for(let item in this.menuItem){
            /*if(item === "/network_interaction_page_telemetry"){
                list.push(<Tab disabled href={item} label={this.menuItem[item].label} key={`menu_item_${this.menuItem[item].num}`} />);
            } else {
                list.push(<Tab href={item} label={this.menuItem[item].label} key={`menu_item_${this.menuItem[item].num}`} />);
            }*/

            list.push(<Tab href={item} label={this.menuItem[item].label} key={`menu_item_${this.menuItem[item].num}`} />);
        }

        return (
            <Row>
                <Col md={12} className="mt-2">
                    <Tabs
                        value={this.getSelectedMenuItem.call(this)}
                        indicatorColor="primary"                        
                        centered >
                        {list}
                    </Tabs>
                </Col>
            </Row>
        );
    }

    /**
                        orientation="vertical"
                        variant="scrollable"
                        aria-label="Vertical tabs example"

 */

    createMenuItemsVertical(){
        let list = [];
        for(let item in this.menuItem){
            list.push(<Tab href={item} label={this.menuItem[item].label} key={`menu_item_${this.menuItem[item].num}`} />);
        }

        return (
            <Tabs
                value={this.getSelectedMenuItem.call(this)}
                indicatorColor="primary"
                orientation="vertical"
                variant="scrollable"
                aria-label="Vertical tabs example" >
                {list}
            </Tabs>
        );
    }

    getSelectedMenuItem(){
        if((typeof this.menuItem[window.location.pathname] === "undefined") || (this.menuItem[window.location.pathname] === null)){           
            return 3;
        }

        return (typeof this.menuItem[window.location.pathname].num !== "undefined") ? this.menuItem[window.location.pathname].num : 0;
    }

    render(){
        return (
            <React.Fragment>
                <CreatingWidgets 
                    widgets={this.state.widgets} 
                    socketIo={this.props.socketIo} 
                    handlerShowModalWindowInfoConnectStatusSources={this.handlerShowModalWindowInfoConnectStatusSources} />
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
                            className="mx-1"
                            size="sm"
                            variant="outline-dark" 
                            onClick={this.handlerShowModalWindowLanCalc} >                           
                            сетевой калькулятор
                        </Button>
                        <Button
                            className="mx-1"
                            size="sm"
                            variant="outline-dark"
                            onClick={this.handlerShowModalWindowEncodeDecoder} >                           
                            декодер
                        </Button>
                    </Col>
                </Row>
                {this.createMenuItems.call(this)}

                {/*this.createMenuItemsVertical.call(this)*/}

                <ModalWindowAddFilteringTask 
                    show={this.state.showModalWindowFiltration}
                    onHide={this.handlerCloseModalWindowFiltration}
                    listSources={this.state.listSources}
                    currentFilteringParameters={{
                        dt: { s: +new Date, e: +new Date },
                        sid: 0,
                        p: "any",
                        f: { 
                            ip: { any: [], src: [], dst: [] },
                            pt: { any: [], src: [], dst: [] },
                            nw: { any: [], src: [], dst: [] },
                        },
                    }}
                    handlerButtonSubmit={this.handlerButtonSubmitWindowFilter} />
                <ModalWindowLanCalc
                    show={this.state.showModalWindowLanCalc}
                    onHide={this.handlerCloseModalWindowLanCalc} />
                <ModalWindowEncodeDecoder
                    show={this.state.showModalWindowEncodeDecoder} 
                    onHide={this.handlerCloseModalWindowEncodeDecoder} />
                <ModalWindowShowInformationConnectionStatusSources 
                    sourceList={this.state.listSources}
                    show={this.state.showModalWindowInfoConnectStatusSources} 
                    onHide={this.handlerCloseModalWindowInfoConnectStatusSources} />
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