import React from "react";
import ReactDOM from "react-dom";
import { Button, Col, Row } from "react-bootstrap";
import { Alert } from "material-ui-lab";
import { LinearProgress } from "@material-ui/core";
import PropTypes from "prop-types";

import CreatingWidgets from "./createWidgets.jsx";
import ModalWindowLanCalc from "../modal_windows/modalWindowLanCalc.jsx";
import ModalWindowEncodeDecoder from "../modal_windows/modalWindowEncodeDecoder.jsx";
import ModalWindowAddFilteringTask from "../modal_windows/modalWindowAddFilteringTask.jsx";
import ModalWindowShowInformationConnectionStatusSources from "../modal_windows/modalWindowShowInformationConnectionStatusSources.jsx";

class CreatePageManagingNetworkInteractions extends React.Component {
    constructor(props) {
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

    connModuleNI() {
        return (typeof this.props.listItems !== "undefined") ? this.props.listItems.connectionModules.moduleNI : false;
    }

    requestEmitter() {
        if (!this.state.connectionModuleNI) {
            return;
        }

        if (window.location.pathname !== "/network_interaction_page_file_download") {
            this.props.socketIo.emit("network interaction: get list tasks to download files", { arguments: { forWidgets: true } });
        }

        if (window.location.pathname !== "/network_interaction_page_statistics_and_analytics") {
            this.props.socketIo.emit("network interaction: get list of unresolved tasks", { arguments: { forWidgets: true } });
        }
    }

    handlerEvents() {
        this.props.socketIo.on("module NI API", (data) => {
            if (data.type === "connectModuleNI") {
                if (data.options.connectionStatus) {
                    this.setState({ "connectionModuleNI": true });

                    location.reload();
                } else {
                    if (!this.state.connectionModuleNI) {
                        return;
                    }

                    let objClone = Object.assign({}, this.state.listSources);
                    for (let sid in objClone) {
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
                            numSourceTelemetryDeviationParameters: 0,
                        },
                        "listSources": objClone,
                    });
                }
            }

            //для списка задач трафик по которым не выгружался
            if (data.type === "get list tasks files not downloaded for widget" || data.type === "get list tasks files not downloaded") {
                //для виджета
                let tmpCopy = Object.assign(this.state.widgets);
                tmpCopy.numTasksNotDownloadFiles = data.options.tntf;
                this.setState({ widgets: tmpCopy });
            }

            //для списка задач не отмеченных пользователем как завершеные
            if (data.type === "get list unresolved task for widget" || data.type === "get list unresolved task") {
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

            for (let source in objCopy.listSources) {
                if (+data.options.sourceID === +source) {
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

            for (let source in objCopy.listSources) {
                if (+data.options.sourceID === +source) {
                    objCopy.listSources[source].appVersion = data.options.appVersion,
                        objCopy.listSources[source].appReleaseDate = data.options.appReleaseDate,

                        this.setState(objCopy);

                    break;
                }
            }
        });
    }

    handlerShowModalWindowFiltration() {
        this.props.socketIo.emit("give me new short source list", {});

        this.setState({ showModalWindowFiltration: true });
    }

    handlerCloseModalWindowFiltration() {
        this.setState({ showModalWindowFiltration: false });
    }

    handlerShowModalWindowShowTaskInformation() {
        this.setState({ showModalWindowShowTaskInformation: true });
    }

    handlerCloseModalWindowShowTaskInformation() {
        this.setState({ showModalWindowShowTaskInformation: false });
    }

    handlerShowModalWindowLanCalc() {
        this.setState({ showModalWindowLanCalc: true });
    }

    handlerCloseModalWindowLanCalc() {
        this.setState({ showModalWindowLanCalc: false });
    }

    handlerShowModalWindowEncodeDecoder() {
        this.setState({ showModalWindowEncodeDecoder: true });
    }

    handlerCloseModalWindowEncodeDecoder() {
        this.setState({ showModalWindowEncodeDecoder: false });
    }

    handlerShowModalWindowInfoConnectStatusSources() {
        this.setState({ showModalWindowInfoConnectStatusSources: true });
    }

    handlerCloseModalWindowInfoConnectStatusSources() {
        this.setState({ showModalWindowInfoConnectStatusSources: false });
    }

    handlerButtonSubmitWindowFilter(objTaskInfo) {
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
    }

    showModuleConnectionError() {
        if (!this.state.connectionModuleNI) {
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

    isDisabledFiltering() {
        //если нет соединения с модулем сетевого взаимодействия
        if (!this.state.connectionModuleNI) {
            return "disabled";
        }

        if (!this.userPermission.management_tasks_filter.element_settings.create.status) {
            return "disabled";
        }

        return (this.userPermission.management_tasks_filter.element_settings.create.status) ? "" : "disabled";
    }

    render() {
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