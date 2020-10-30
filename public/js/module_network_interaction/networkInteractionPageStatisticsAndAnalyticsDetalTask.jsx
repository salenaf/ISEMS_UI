import React from "react";
import ReactDOM from "react-dom";
import { Badge, Button, Col, Row, OverlayTrigger, Tooltip, Spinner } from "react-bootstrap";
import PropTypes from "prop-types";

import { ModalWindowConfirmCloseTask } from "../modal_windows/modalWindowConfirmCloseTask.jsx";

class CreatePageStatisticsAndAnalyticsDetalTask extends React.Component {
    constructor(props){
        super(props);

        this.state = {
            hideButtonMarkTask: false,
            showModalWindowConfirmCloseTask: false,
            commonAnalyticsInformationAboutTask: {
                sourceID:0,
                generalInformationAboutTask: {
                    taskProcessed: false,
                    dateTimeProcessed: 0,
                    detailDescription: { userNameClosedProcess: "", description: "" },
                },
                filteringOption:{
                    dateTime: { start: 0, end: 0 },
                    proto: "any",
                    networkFilter: {
                        ip:{ any:[], src:[], dst:[] },
                        nw:{ any:[], src:[], dst:[] },
                        pt:{ any:[], src:[], dst:[] },
                    },
                },
                commonInformationAboutReceivedFiles:{
                    numberFilesTotal: 0,
                    downloadTaskStatus: "",
                    filteringTaskStatus: "",               
                    numberFilesDownloaded: 0,
                    sizeFilesFoundResultFiltering: 0,
                    pathDirectoryStorageDownloadedFiles: "",
                },
                detailedInformationAboutReceivedFiles: {
                    numberFilesProcessed: 0,
                    sizeFilesProcessed: 0,
                },
            },
        };

        this.formatterDate = this.formatterDate.bind(this);
        this.formatterNumber = this.formatterNumber.bind(this);
        this.buttonBackArrow = this.buttonBackArrow.bind(this);
        this.handlerCloseTask = this.handlerCloseTask.bind(this);
        this.getListNetworkParameters = this.getListNetworkParameters.bind(this);
        this.handlerShowModalWindowCloseTask = this.handlerShowModalWindowCloseTask.bind(this);
        this.handlerCloseModalWindowCloseTask = this.handlerCloseModalWindowCloseTask.bind(this);

        this.handlerEvents.call(this);
        this.getInformationAboutTask.call(this);
    }

    handlerEvents(){
        this.props.socketIo.on("module NI API", (data) => {
            if(data.type === "commonAnalyticsInformationAboutTaskID"){   

                let tmpCopy = Object.assign(this.state.commonAnalyticsInformationAboutTask);
                tmpCopy = {
                    sourceID:data.options.tp.sid,
                    generalInformationAboutTask: {
                        taskProcessed: data.options.tp.giat.tp,
                        dateTimeProcessed: data.options.tp.giat.dtp,
                        detailDescription: { 
                            userNameClosedProcess: data.options.tp.giat.dd.uncp, 
                            description: data.options.tp.giat.dd.dpr 
                        },
                    },
                    filteringOption:{
                        dateTime: { 
                            start: data.options.tp.ifo.dt.s, 
                            end: data.options.tp.ifo.dt.e 
                        },
                        proto: data.options.tp.ifo.p,
                        networkFilter: {
                            ip:data.options.tp.ifo.nf.ip,
                            nw:data.options.tp.ifo.nf.nw,
                            pt:data.options.tp.ifo.nf.pt,
                        },
                    },
                    commonInformationAboutReceivedFiles:{
                        numberFilesTotal: data.options.tp.ciarf.nft,
                        downloadTaskStatus: data.options.tp.ciarf.dts,
                        filteringTaskStatus: data.options.tp.ciarf.fts,               
                        numberFilesDownloaded: data.options.tp.ciarf.nfd,
                        sizeFilesFoundResultFiltering: data.options.tp.ciarf.sffrf,
                        pathDirectoryStorageDownloadedFiles: data.options.tp.ciarf.pdsdf,
                    },
                    detailedInformationAboutReceivedFiles: {
                        numberFilesProcessed: 0,
                        sizeFilesProcessed: 0,
                    },
                };
                this.setState({ 
                    hideButtonMarkTask: data.options.tp.giat.tp,
                    commonAnalyticsInformationAboutTask: tmpCopy, 
                }); 
            }

            if(data.type === "successMarkTaskAsCompleted"){
                if(this.props.listItems.urlQueryParameters.taskID === data.options.taskID){                   
                    this.setState({ hideButtonMarkTask: true });
                }
            }
        });
    }

    handlerShowModalWindowCloseTask(){
        this.setState({ showModalWindowConfirmCloseTask: true });
    }

    handlerCloseModalWindowCloseTask(){
        this.setState({ showModalWindowConfirmCloseTask: false });
    }

    handlerCloseTask(data){
        this.props.socketIo.emit("network interaction: mark an task as completed", {
            arguments: { 
                taskID: data.taskID,
                description: data.description,
            },
        });

        this.setState({ showModalWindowConfirmCloseTask: false });
    }

    buttonBackArrow(){
        window.history.back();
    }

    formatterDate(){
        return new Intl.DateTimeFormat("ru-Ru", {
            timeZone: "Europe/Moscow",
            day: "numeric",
            month: "numeric",
            year: "numeric",
            hour: "numeric",
            minute: "numeric",
        });
    }

    formatterNumber(){
        return new Intl.NumberFormat("ru");
    }

    getInformationAboutTask(){
        this.props.socketIo.emit("network interaction: get analytics information about task id", {
            arguments: { taskID: this.props.listItems.urlQueryParameters.taskID } 
        });
    }

    getStatusFiltering(ts){   
        if(ts === "wait"){
            return <small className="text-info">готовится к выполнению</small>;
        } else if(ts === "refused"){
            return <small className="text-danger">oтклонена</small>;
        } else if(ts === "execute"){
            return <small className="text-primary">выполняется</small>;
        } else if(ts === "complete"){
            return <small className="text-success">завершена успешно</small>;
        } else if(ts === "stop"){
            return <small className="text-warning">остановлена пользователем</small>;
        } else {
            return <small>ts</small>;
        }
    }

    getStatusDownload(ts){   
        if(ts === "wait"){
            return <small className="text-info">готовится к выполнению</small>;
        } else if(ts === "refused"){
            return <small className="text-danger">oтклонена</small>;
        } else if(ts === "execute"){
            return <small className="text-primary">выполняется</small>;       
        } else if(ts === "complete"){
            return <small className="text-success">завершена успешно</small>;       
        } else if(ts === "stop"){
            return <small className="text-warning">остановлена пользователем</small>;
        } else if(ts === "not executed"){
            return <small className="text-light bg-dark">не выполнялась</small>;
        } else {
            return <small>ts</small>;
        }
    }

    createButtonCloseTask(){
        if(this.state.hideButtonMarkTask){
            return;
        }

        let isDisabled = "disabled";
        let caiat = this.state.commonAnalyticsInformationAboutTask;
        let dts = caiat.commonInformationAboutReceivedFiles.downloadTaskStatus === "complete";
        let fts = caiat.commonInformationAboutReceivedFiles.filteringTaskStatus === "complete";
        let userPermission = this.props.listItems.userPermissions.management_uploaded_files.element_settings.status_change.status; 

        if(dts && fts && userPermission && !caiat.generalInformationAboutTask.taskProcessed){           
            isDisabled = "";
        }

        return (
            <Button
                className="mx-1"
                size="sm"
                variant="outline-danger"
                onClick={this.handlerShowModalWindowCloseTask}
                disabled={isDisabled} >
                    закрыть задачу
            </Button>
        );
    }

    createChunkCommonInformation(){
        let ciarf = this.state.commonAnalyticsInformationAboutTask.commonInformationAboutReceivedFiles;
        let diarf = this.state.commonAnalyticsInformationAboutTask.detailedInformationAboutReceivedFiles;

        return (
            <React.Fragment>
                <Row className="text-muted mb-n2">
                    <Col md={6} className="text-left"><small>фильтрация: </small></Col>
                    <Col md={6} className="text-right">{this.getStatusFiltering.call(this, ciarf.filteringTaskStatus)}</Col>
                </Row>
                <Row className="text-muted mb-n2">
                    <Col md={6} className="text-left"><small>выгрузка файлов: </small></Col>
                    <Col md={6} className="text-right">{this.getStatusDownload.call(this, ciarf.downloadTaskStatus)}</Col>
                </Row>
                <Row className="text-muted mb-n2">
                    <Col md={6} className="text-left"><small>всего файлов:</small></Col>
                    <Col md={6} className="text-right"><small><strong>{this.formatterNumber().format(ciarf.numberFilesTotal)}</strong> шт.</small></Col>
                </Row>
                <Row className="text-muted mb-n2">
                    <Col md={6} className="text-left"><small>файлов выгружено:</small></Col>
                    <Col md={6} className="text-right"><small><strong>{this.formatterNumber().format(ciarf.numberFilesDownloaded)}</strong> шт.</small></Col>
                </Row>
                <Row className="text-muted mb-n2">
                    <Col md={6} className="text-left"><small>общим размером:</small></Col>
                    <Col md={6} className="text-right"><small><strong>{this.formatterNumber().format(ciarf.sizeFilesFoundResultFiltering)}</strong> байт</small></Col>
                </Row>
                <Row className="text-muted mb-n2">
                    <Col md={6} className="text-left"><small>файлов обработано:</small></Col>
                    <Col md={6} className="text-right"><small><strong>{this.formatterNumber().format(diarf.numberFilesProcessed)}</strong> шт.</small></Col>
                </Row>
                <Row className="text-muted mb-n2">
                    <Col md={6} className="text-left"><small>общим размером:</small></Col>
                    <Col md={6} className="text-right"><small><strong>{this.formatterNumber().format(diarf.sizeFilesProcessed)}</strong> байт</small></Col>
                </Row>
                <Row className="text-muted mb-n2">
                    <Col md={12} className="text-left">
                        <small>место нахождения файлов: </small>
                    </Col>
                </Row>
            </React.Fragment>
        );
    }

    getListNetworkParameters(type){
        let pf = this.state.commonAnalyticsInformationAboutTask.filteringOption.networkFilter;       
        let getListDirection = (d) => {
            if((pf[type][d] === null) || (pf[type][d].length === 0)){
                return { value: "", success: false };
            }

            let result = pf[type][d].map((item) => {
                if(d === "src"){
                    return (<div className="ml-4" key={`elem_${type}_${d}_${item}`}>
                        <small className="text-info">{d}&#8592; </small><small>{item}</small>
                    </div>); 
                }
                if(d === "dst"){
                    return (<div className="ml-4" key={`elem_${type}_${d}_${item}`}>
                        <small className="text-info">{d}&#8594; </small><small>{item}</small>
                    </div>); 
                }

                return (<div className="ml-4" key={`elem_${type}_${d}_${item}`}>
                    <small className="text-info">{d}&#8596; </small><small>{item}</small>
                </div>); 
            });

            return { value: result, success: true };
        };

        let resultAny = getListDirection("any");
        let resultSrc = getListDirection("src");
        let resultDst = getListDirection("dst");

        return (
            <React.Fragment>
                <div>{resultAny.value}</div>
                {(resultAny.success && (resultSrc.success || resultDst.success)) ? <div className="text-danger text-center my-n2">&laquo;<small>ИЛИ</small>&raquo;</div> : <div></div>}                   
                <div>{resultSrc.value}</div>
                {(resultSrc.success && resultDst.success) ? <div className="text-danger text-center  my-n2">&laquo;<small>И</small>&raquo;</div> : <div></div>}                   
                <div>{resultDst.value}</div>
            </React.Fragment>
        );
    }

    createNetworkParameters(){
        return (
            <React.Fragment>
                <Row>
                    <Col sm="3" className="text-center">
                        <Badge variant="dark">ip адрес</Badge>
                    </Col>
                    <Col sm="2" className="text-danger text-center">&laquo;<small>ИЛИ</small>&raquo;</Col>
                    <Col sm="3" className="text-center">
                        <Badge variant="dark">сеть</Badge>
                    </Col>
                    <Col sm="1" className="text-danger text-center">&laquo;<small>И</small>&raquo;</Col>
                    <Col sm="3" className="text-center">
                        <Badge variant="dark">сетевой порт</Badge>
                    </Col>
                </Row>
                <Row>
                    <Col sm="4">{this.getListNetworkParameters("ip")}</Col>
                    <Col sm="1"></Col>
                    <Col sm="4">{this.getListNetworkParameters("nw")}</Col>
                    <Col sm="3">{this.getListNetworkParameters("pt")}</Col>
                </Row>
            </React.Fragment>
        );
    }

    createChunkFilteringOptions(){
        let fo = this.state.commonAnalyticsInformationAboutTask.filteringOption;

        return (
            <div className="panel-body chat-widget-main">
                <Row>
                    <Col md={9} className="text-muted text-left">
                        <small>
                            дата и время,
                            начальное: <strong>{this.formatterDate().format(fo.dateTime.start * 1000)}</strong>, 
                            конечное: <strong>{this.formatterDate().format(fo.dateTime.end * 1000)}</strong>
                        </small>
                    </Col>
                    <Col md={3} className="text-muted text-right"><small>сет. протокол: <strong>{(fo.proto === "any") ? "любой" : fo.proto}</strong></small></Col>
                </Row>
                <Row><Col md={12}>{this.createNetworkParameters.call(this)}</Col></Row>
            </div>
        );
    }

    createChunkInformationWhoClosedTask(){      
        let giat = this.state.commonAnalyticsInformationAboutTask.generalInformationAboutTask;
        if(!giat.taskProcessed){
            return;
        }

        return (
            <React.Fragment>
                <Row className="text-muted mb-n2">
                    <Col md={2} className="text-left"><small>cтатус задачи: <span className="text-danger">закрыта</span></small></Col>
                    <Col md={2} className="text-left"><small>дата: {this.formatterDate().format(giat.dateTimeProcessed*1000)}</small></Col>
                    <Col md={8} className="text-right"><small>пользователь: {giat.detailDescription.userNameClosedProcess}</small></Col>
                </Row>
                <Row className="text-muted">
                    <Col md={2} className="text-left"><small>примечание:</small></Col>
                    <Col md={10} className="text-left mt-2 my_line_spacing"><small><i>{giat.detailDescription.description}</i></small></Col>
                </Row>
            </React.Fragment>
        );
    }

    createMainBody(){
        if(this.state.commonAnalyticsInformationAboutTask.sourceID === 0){
            return (
                <Row className="mt-4">
                    <Col>
                        <Spinner animation="border" role="status" variant="primary">
                            <span className="sr-only">Загрузка...</span>
                        </Spinner>
                    </Col>
                </Row>
            );
        }

        return (
            <React.Fragment>
                <Row className="mt-2">
                    <Col md={4}>{this.createChunkCommonInformation.call(this)}</Col>
                    <Col md={8}>{this.createChunkFilteringOptions.call(this)}</Col>
                </Row>
                <Row className="mb-n2 text-muted">
                    <Col md={12} className="text-center text-info">
                        <small>{this.state.commonAnalyticsInformationAboutTask.commonInformationAboutReceivedFiles.pathDirectoryStorageDownloadedFiles}</small>
                    </Col>
                </Row>
            </React.Fragment>
        );
    }

    render(){
        return (
            <React.Fragment>
                <Row className="pt-3">
                    <Col md={2} className="text-left">
                        <OverlayTrigger
                            key={"tooltip_back_arrow_img"}
                            placement="right"
                            overlay={<Tooltip>назад</Tooltip>}>
                            <a href="#" onClick={this.buttonBackArrow}>
                                <img className="clickable_icon" width="36" height="36" src="../images/icons8-back-arrow-48.png" alt="назад"></img>
                            </a>
                        </OverlayTrigger>
                    </Col>
                    <Col md={8} className="mt-1">
                        <Row>
                            <Col>
                                Источник №{this.props.listItems.urlQueryParameters.sourceID} (<i>{this.props.listItems.urlQueryParameters.sourceName}</i>)
                            </Col>
                        </Row>
                        <Row>
                            <Col className="text-muted mt-n1">
                            ID задачи: <span className="text-info">{this.props.listItems.urlQueryParameters.taskID}</span>
                            &nbsp;(дата создания: <i>{this.formatterDate().format(this.props.listItems.urlQueryParameters.taskBeginTime)}</i>)
                            </Col>
                        </Row>
                    </Col>
                    <Col md={2} className="text-right mt-1">
                        {this.createButtonCloseTask.call(this)}
                    </Col>
                </Row>
                {this.createChunkInformationWhoClosedTask.call(this)}
                {this.createMainBody.call(this)}
                <Row>
                    <Col md={12} className="mt-4"></Col>
                </Row>

                <ModalWindowConfirmCloseTask 
                    show={this.state.showModalWindowConfirmCloseTask}
                    onHide={this.handlerCloseModalWindowCloseTask}
                    commonParameters={{ taskID: this.props.listItems.urlQueryParameters.taskID }}
                    handlerConfirm={this.handlerCloseTask} />
            </React.Fragment>
        );
    }
}

CreatePageStatisticsAndAnalyticsDetalTask.propTypes = {
    socketIo: PropTypes.object.isRequired,
    listItems: PropTypes.object.isRequired,
};

ReactDOM.render(<CreatePageStatisticsAndAnalyticsDetalTask
    socketIo={socket}
    listItems={receivedFromServer} />, document.getElementById("main-page-content"));
