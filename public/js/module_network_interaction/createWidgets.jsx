import React from "react";
import { Card } from "react-bootstrap";
import PropTypes from "prop-types";

export default class CreatingWidgets extends React.Component {
    constructor(props){
        super(props);

        this.state = {
            filtration: new Set(),
            download: new Set(),
            telemetryDeviationParameters: 0,
        };

        this.handlerEvents.call(this);
        this.requestEmitter.call(this);

        this.handlerClickOnWidgetProcessingTask = this.handlerClickOnWidgetProcessingTask.bind(this);
        this.handlerClickOnWidgetUnresolvedTask = this.handlerClickOnWidgetUnresolvedTask.bind(this);
        this.handlerClickOnWidgetNotDownloadTask = this.handlerClickOnWidgetNotDownloadTask.bind(this);
        this.handlerClickOnWidgetTelemetryDeviation = this.handlerClickOnWidgetTelemetryDeviation.bind(this);
    }

    requestEmitter(){
        this.props.socketIo.emit("network interaction: get list source with deviation parameters", {});
    }

    handlerEvents(){
        this.props.socketIo.on("module NI API", (msg) => {
            if(msg.type === "filtrationProcessing"){          
                let objCopy = Object.assign({}, this.state);

                if((msg.options.status === "complete") || (msg.options.status === "refused")){
                    objCopy.filtration.delete(msg.options.taskID);
                } else {
                    objCopy.filtration.add(msg.options.taskID);
                }

                this.setState(objCopy);
            }

            if(msg.type === "downloadProcessing"){          
                let objCopy = Object.assign({}, this.state);

                if((msg.options.status === "complete") || (msg.options.status === "refused")){
                    objCopy.download.delete(msg.options.taskID);
                
                    //если выгрузка файлов завершена успешно
                    if(msg.options.status === "complete"){
                        this.props.socketIo.emit("network interaction: get list of unresolved tasks", { arguments: { forWidgets: true } });
                    }
                } else {
                    objCopy.download.add(msg.options.taskID);
                }                                                                                                                                                                                                                                                                                                                                                                                                                   

                this.setState(objCopy);
            }

            if(msg.type === "telemetryDeviationParameters"){
                this.setState({ telemetryDeviationParameters: msg.options.length });
            }
        });
    }

    handlerClickOnWidgetProcessingTask(){
        window.location.href = "/network_interaction";
    }

    handlerClickOnWidgetUnresolvedTask(){
        window.location.href = "/network_interaction_page_statistics_and_analytics";
    }

    handlerClickOnWidgetNotDownloadTask(){
        window.location.href = "/network_interaction_page_file_download";
    }

    handlerClickOnWidgetTelemetryDeviation(){
        window.location.href = "/network_interaction_page_source_telemetry";
    }

    render(){
        return (
            <div className="row d-flex justify-content-center">
                <Card className="ml-3 clicabe_cursor" border="success" style={{ width: "10rem" }} onClick={this.props.handlerShowModalWindowInfoConnectStatusSources}>
                    <small>источников</small>
                    <span className="my-n2 text-success">{this.props.widgets.numConnect}</span>
                    <small className="text-muted">подключено</small>
                </Card>
                <Card className="ml-3 clicabe_cursor" border="danger" style={{ width: "10rem" }} onClick={this.props.handlerShowModalWindowInfoConnectStatusSources}>
                    <small>источников</small>
                    <span className="my-n2 text-danger">{this.props.widgets.numDisconnect}</span>
                    <small className="text-muted">не доступно</small>
                </Card>
                <Card 
                    onClick={this.handlerClickOnWidgetProcessingTask}
                    className="ml-3 clicabe_cursor" 
                    border="dark" 
                    style={{ width: "10rem" }}>
                    <small>фильтрация</small>
                    <span className="my-n2">{this.state.filtration.size}</span>
                    <small className="text-muted">выполняется</small>
                </Card>
                <Card 
                    onClick={this.handlerClickOnWidgetNotDownloadTask}
                    className="ml-3 clicabe_cursor" 
                    border="info" 
                    style={{ width: "13rem" }}>
                    <small>выгрузка файлов</small>
                    <span className="my-n2 text-info">{this.state.download.size} / {this.props.widgets.numTasksNotDownloadFiles}</span>
                    <small className="text-muted"> выполняется / доступна</small>
                </Card>
                <Card 
                    onClick={this.handlerClickOnWidgetUnresolvedTask}
                    className="ml-3 clicabe_cursor" 
                    border="info" 
                    style={{ width: "13rem" }}>
                    <small>выгруженные файлы</small>
                    <span className="my-n2 text-info">{this.props.widgets.numUnresolvedTask}</span>
                    <small className="text-muted">не рассмотренны</small>
                </Card>
                <Card 
                    onClick={this.handlerClickOnWidgetTelemetryDeviation}
                    className="ml-3 clicabe_cursor" 
                    border="danger" 
                    style={{ width: "12rem" }}>
                    <small>телеметрия источников</small>
                    <span className="my-n2 text-danger">{this.state.telemetryDeviationParameters}</span>
                    <small className="text-muted">требуют внимание</small>
                </Card>
            </div>
        );
    }
}

CreatingWidgets.propTypes = {
    widgets: PropTypes.object.isRequired,
    socketIo: PropTypes.object.isRequired,
    handlerShowModalWindowInfoConnectStatusSources: PropTypes.func.isRequired,
};