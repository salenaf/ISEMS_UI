import React from "react";
import { Badge, Card, Col, ProgressBar, Row } from "react-bootstrap";
import PropTypes from "prop-types";

export default class CreateBodyDynamics extends React.Component {
    constructor(props){
        super(props);

        this.state = {
            "filtration": {},
            "download": {},
        };

        this.deleteItemByTimeout = this.deleteItemByTimeout.bind(this);

        this.handlerEvents.call(this);
    }

    //для удаление виджитов по мере завершения задач
    deleteItemByTimeout(typeProcessing, id){
        setTimeout(() => {
            let objCopy = Object.assign({}, this.state);
            delete(objCopy[typeProcessing][id]);
            this.setState(objCopy);
        }, 5000);
    }

    handlerEvents(){
        this.props.socketIo.on("module NI API", (msg) => {
            if(msg.type === "filtrationProcessing"){
                let objCopy = Object.assign({}, this.state);
                objCopy.filtration[msg.options.taskID] = msg.options;
                this.setState(objCopy);

                if((msg.options.status === "complete") || (msg.options.status === "refused") || (msg.options.status === "stop")){
                    this.deleteItemByTimeout("filtration", msg.options.taskID);
                }
            }

            if(msg.type === "downloadProcessing"){
                let objCopy = Object.assign({}, this.state);
                objCopy.download[msg.options.taskID] = msg.options;
                this.setState(objCopy);

                if((msg.options.status === "complete") || (msg.options.status === "refused") || (msg.options.status === "stop")){
                    this.deleteItemByTimeout("download", msg.options.taskID);
                }
            }
        });
    }

    showModalWindow(objInfo){
        this.props.handlerModalWindowShowTaskTnformation(objInfo);
        this.sendRequestShowInfo.call(this, objInfo.taskID);
    }

    sendRequestShowInfo(taskID){
        this.props.socketIo.emit("network interaction: show info about all task", {
            arguments: { taskID: taskID } 
        });
    }

    createFiltrationWidget(){
        let formatter = new Intl.NumberFormat("ru");
        let list = [];

        for(let pf in this.state.filtration){
            let numAllFiles = this.state.filtration[pf].parameters.numAllFiles;
            let numProcessedFiles = this.state.filtration[pf].parameters.numProcessedFiles;
            let percent = (numProcessedFiles*100) / numAllFiles;

            let numFindFiles = this.state.filtration[pf].parameters.numFindFiles;
            let sizeAllFiles = this.state.filtration[pf].parameters.sizeAllFiles;
            let sizeFindFiles = this.state.filtration[pf].parameters.sizeFindFiles;

            let objInfo = {
                sourceID: this.state.filtration[pf].sourceID, 
                sourceName: this.state.filtration[pf].name,
                taskID: this.state.filtration[pf].taskIDModuleNI,
            };

            let progress = <div className="pl-2 pr-2"><ProgressBar now={percent} label={`${numProcessedFiles} / ${numAllFiles}`}/></div>;

            if(this.state.filtration[pf].status === "complete"){
                progress = <div className="text-success mt-n1 mb-n1">фильтрация сетевого трафика завершена</div>;
            }

            if((this.state.filtration[pf].status === "refused") || (this.state.filtration[pf].status === "stop")){
                let msg = <small className="text-danger">задача отклонена. Возможно не найдены файлы удовлетворяющие заданным параметрам.</small>;
                if(this.state.filtration[pf].status === "stop"){
                    msg = <small className="text-success">задача успешно остановлена.</small>;
                }

                list.push(
                    <Row key={`row_card_filter_${pf}`}>
                        <Col md={3} className="text-muted text-right">
                            <Row className="mb-n2"><Col><small>источник: <i><strong>{this.state.filtration[pf].sourceID}</strong></i></small></Col></Row>
                            <Row className="mb-n2"><Col><small>название: <i><strong>{this.state.filtration[pf].name}</strong></i></small></Col></Row>
                            <Row className="mb-n2"><Col><small>действие: </small><Badge variant="dark">фильтрация файлов</Badge></Col></Row>
                        </Col>
                        <Col md={9}>
                            <Card 
                                className="mb-3 clicabe_cursor text-muted" 
                                key={`card_filter_${pf}`}
                                onClick={this.showModalWindow.bind(this, objInfo)} >
                                <small className="mb-n2">{`файлов найдено / обработано / всего: ${numFindFiles} / ${numProcessedFiles} / ${numAllFiles}`}</small>
                                <div className="pl-2 pr-2 mb-n2">{msg}</div>
                                <small>{`найдено: ${formatter.format(sizeFindFiles)} байт, всего: ${formatter.format(sizeAllFiles)} байт`}</small>
                            </Card>
                        </Col>
                    </Row>
                );

                continue;
            }            

            list.push(
                <Row key={`row_card_filter_${pf}`}>
                    <Col md={3} className="text-muted text-right">
                        <Row className="mb-n2"><Col><small>источник: <i><strong>{this.state.filtration[pf].sourceID}</strong></i></small></Col></Row>
                        <Row className="mb-n2"><Col><small>название: <i><strong>{this.state.filtration[pf].name}</strong></i></small></Col></Row>
                        <Row className="mb-n2"><Col><small>действие: </small><Badge variant="dark">фильтрация файлов</Badge></Col></Row>
                    </Col>
                    <Col md={9}>
                        <Card 
                            className="mb-3 clicabe_cursor text-muted" 
                            key={`card_filter_${pf}`}
                            onClick={this.showModalWindow.bind(this, objInfo)} >
                            <small>{`файлов найдено / обработано / всего: ${numFindFiles} / ${numProcessedFiles} / ${numAllFiles}`}</small>
                            {progress}
                            <small>{`найдено: ${formatter.format(sizeFindFiles)} байт, всего: ${formatter.format(sizeAllFiles)} байт`}</small>
                        </Card>
                    </Col>
                </Row>
            );
        }

        return list;
    }

    createDownloadWidget(){
        let list = [];

        for(let pf in this.state.download){
            let fileName = (typeof this.state.download[pf].parameters.dfi.fileName !== "undefined") ? this.state.download[pf].parameters.dfi.fileName: "";
            let filePercent = this.state.download[pf].parameters.dfi.acceptedSizePercent;
            let fdt = this.state.download[pf].parameters.numberFilesTotal;
            let fd = this.state.download[pf].parameters.numberFilesDownloaded;
            let fde = this.state.download[pf].parameters.numberFilesDownloadedError;


            let objInfo = {
                sourceID: this.state.download[pf].sourceID, 
                sourceName: this.state.download[pf].name,
                taskID: this.state.download[pf].taskIDModuleNI,
            };

            let progress = <div className="pl-2 pr-2"><ProgressBar now={filePercent} label={`${filePercent}%`}/></div>;

            if(this.state.download[pf].status === "complete"){
                progress = <div className="text-success mt-n1 mb-n1">загрузка файлов завершена</div>;
            }

            if((this.state.download[pf].status === "refused") || (this.state.download[pf].status === "stop")){
                let msg = <small className="text-danger">задача отклонена. Возможно не найдены файлы удовлетворяющие заданным параметрам.</small>;
                if(this.state.download[pf].status ===  "stop"){
                    msg = <small className="text-success">задача успешно остановлена.</small>;
                }

                list.push(
                    <Row key={`row_card_filter_${pf}`}>
                        <Col md={3} className="text-muted text-right">
                            <Row className="mb-n2"><Col><small>источник: <i><strong>{this.state.download[pf].sourceID}</strong></i></small></Col></Row>
                            <Row className="mb-n2"><Col><small>название: <i><strong>{this.state.download[pf].name}</strong></i></small></Col></Row>
                            <Row className="mb-n2"><Col><small>действие: </small><Badge variant="info">загрузка файлов</Badge></Col></Row>
                        </Col>
                        <Col md={9}>
                            <Card 
                                className="mb-3 clicabe_cursor text-muted" 
                                key={`card_filter_${pf}`}
                                onClick={this.showModalWindow.bind(this, objInfo)} >
                                <small className="text-muted">
                                    файлов загружено / с ошибкой / всего: 0 / 0 / 0
                                </small>
                                <div className="pl-2 pr-2 mb-n2">{msg}</div>
                                <small>загружается файл: </small>
                            </Card>
                        </Col>
                    </Row>
                );

                continue;
            }            

            list.push(
                <Row key={`row_card_filter_${pf}`}>
                    <Col md={3} className="text-muted text-right">
                        <Row className="mb-n2"><Col><small>источник: <i><strong>{this.state.download[pf].sourceID}</strong></i></small></Col></Row>
                        <Row className="mb-n2"><Col><small>название: <i><strong>{this.state.download[pf].name}</strong></i></small></Col></Row>
                        <Row className="mb-n2"><Col><small>действие: </small><Badge variant="info">загрузка файлов</Badge></Col></Row>
                    </Col>
                    <Col md={9}>
                        <Card 
                            className="mb-3 clicabe_cursor text-muted" 
                            key={`card_filter_${pf}`}
                            onClick={this.showModalWindow.bind(this, objInfo)} >
                            <small className="text-muted">
                                {`файлов загружено / с ошибкой / всего: ${fd} / ${fde} / ${fdt}`}
                            </small>
                            {progress}
                            <small>{`загружается файл: ${fileName}`}</small>
                        </Card>
                    </Col>
                </Row>
            );
        }

        return list;
    }

    render(){
        return (
            <React.Fragment>
                <br/>
                {this.createFiltrationWidget.call(this)}
                {this.createDownloadWidget.call(this)}
            </React.Fragment>
        );
    }
}

CreateBodyDynamics.propTypes = {
    socketIo: PropTypes.object.isRequired,
    handlerModalWindowShowTaskTnformation: PropTypes.func.isRequired,
};