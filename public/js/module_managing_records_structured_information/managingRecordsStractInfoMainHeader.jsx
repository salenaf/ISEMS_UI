import React from "react";
import ReactDOM from "react-dom";
import { Button, Col, Row } from "react-bootstrap";
import { Alert } from "material-ui-lab";
import { LinearProgress } from "@material-ui/core";
import PropTypes from "prop-types";

class CreatePageManagingmanagingRecordsStractInfo extends React.Component {
    constructor(props) {
        super(props);

        this.state = {
            "connectModuleMRSICT": this.connectModuleMRSICT.call(this),
        };

        this.userPermission = this.props.listItems.userPermissions;

        this.handlerEvents.call(this);
        this.requestEmitter.call(this);
    }

    connectModuleMRSICT() {
        return (typeof this.props.listItems !== "undefined") ? this.props.listItems.connectionModules.moduleMRSICT : false;
    }

    requestEmitter() {
        if (!this.state.connectModuleMRSICT) {
            return;
        }

        /*
        if (window.location.pathname !== "/network_interaction_page_file_download") {
            this.props.socketIo.emit("network interaction: get list tasks to download files", { arguments: { forWidgets: true } });
        }

        if (window.location.pathname !== "/network_interaction_page_statistics_and_analytics") {
            this.props.socketIo.emit("network interaction: get list of unresolved tasks", { arguments: { forWidgets: true } });
        }
        */
    }

    handlerEvents() {
        this.props.socketIo.on("module_MRSICT-API", (data) => {

            console.log(`func 'handlerEvents', Event: 'module_MRSICT-API' ${data.options.connectionStatus}`);

            if (data.type === "connectModuleMRSICT") {
                if (data.options.connectionStatus) {
                    this.setState({ "connectModuleMRSICT": true });

                    location.reload();
                } else {
                    if (!this.state.connectModuleMRSICT) {
                        return;
                    }

                    this.setState({ "connectModuleMRSICT": false });

                    /*
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
                    */
                }
            }
        });

        /*
        this.props.socketIo.on("module-ni:change sources connection", (data) => {
            let tmpCopy = Object.assign(this.state.widgets);
            tmpCopy.numConnect = data.numConnect;
            tmpCopy.numDisconnect = data.numDisconnect;
            this.setState({ widgets: tmpCopy });
        });
        */
    }

    showModuleConnectionError() {
        if (!this.state.connectModuleMRSICT) {
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

    render() {

        /** МОДАЛЬНЫЕ ОКНА ЛУЧШЕ ДЕЛАТЬ ЗДЕСЬ, во всяком случае какую то часть окон */

        return (
            <React.Fragment>
                {this.showModuleConnectionError.call(this)}
                <Row className="pt-4">
                    <Col md={12} className="text-right">
                        <Button
                            className="mx-1"
                            size="sm"
                            variant="outline-danger"
                            /*disabled={this.isDisabledFiltering.call(this)}
                            onClick={this.handlerShowModalWindowFiltration} */>
                            фильтрация
                        </Button>
                        <Button
                            className="mx-1"
                            size="sm"
                            variant="outline-dark"
                            /*onClick={this.handlerShowModalWindowLanCalc} */>
                            сетевой калькулятор
                        </Button>
                        <Button
                            className="mx-1"
                            size="sm"
                            variant="outline-dark"
                            /*onClick={this.handlerShowModalWindowEncodeDecoder} */>
                            декодер
                        </Button>
                    </Col>
                </Row>
            </React.Fragment>
        );
    }
}

CreatePageManagingmanagingRecordsStractInfo.propTypes = {
    socketIo: PropTypes.object.isRequired,
    listItems: PropTypes.object.isRequired,
};

ReactDOM.render(<CreatePageManagingmanagingRecordsStractInfo
    socketIo={socket}
    listItems={receivedFromServer} />, document.getElementById("header-page-content"));