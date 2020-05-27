import React from "react";
import { Col, Card, ProgressBar, Row, Button, Tab, Tabs } from "react-bootstrap";
import PropTypes from "prop-types";

export default class CreateBodyDynamics extends React.Component {
    constructor(props){
        super(props);

        this.state = {
            "filtration": {},
            "download": {},
        };

        this.handlerEvents.call(this);

        this.deleteItemByTimeout = this.deleteItemByTimeout.bind(this);
    }

    deleteItemByTimeout(typeProcessing, id){
        console.log("func 'deleteItemByTimeout', START...");

        setTimeout(() => {
            console.log("delete ---");

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

                if(msg.options.status === "complete"){
                    this.deleteItemByTimeout("filtration", msg.options.taskID);
                }
            }
        });
    }

    createFiltrationWidget(){

        /**
 * Нужно сделать формирование шаблона на сонове статуса задачи
 * усли статус "complete" то шаблон должен быть другой. 
 * 
 */

        var formatter = new Intl.NumberFormat("ru");
        let list = [];
        for(let pf in this.state.filtration){
            let numAllFiles = this.state.filtration[pf].parameters.numAllFiles;
            let numProcessedFiles = this.state.filtration[pf].parameters.numProcessedFiles;
            let percent = (numProcessedFiles*100) / numAllFiles;

            let numFindFiles = this.state.filtration[pf].parameters.numFindFiles;
            let sizeAllFiles = this.state.filtration[pf].parameters.sizeAllFiles;
            let sizeFindFiles = this.state.filtration[pf].parameters.sizeFindFiles;

            let progress = <ProgressBar now={percent} label={`${numProcessedFiles} / ${numAllFiles}`}/>;

            if(this.state.filtration[pf].status === "complete"){
                progress = <span className="text-success">фильтрация сетевого трафика завершена</span>;
            }

            list.push(
                <Card className="mb-3" key={`card_filter_${pf}`}>
                    {`${this.state.filtration[pf].sourceID} - ${this.state.filtration[pf].name}`}
                    <div className="pl-2 pr-2">{progress}</div>
                    <small className="text-muted">
                        {`файлов найдено / обработано / всего: ${numFindFiles} / ${numProcessedFiles} / ${numAllFiles} (найдено: ${formatter.format(sizeFindFiles)} байт, всего: ${formatter.format(sizeAllFiles)} байт)`}
                    </small>
                </Card>
            );
        }

        return list;
    }

    render(){
        return (
            <React.Fragment>
                <Card className="mb-3">
                    {"1023 - Sensor MER (задача: скачивание файлов, это только примеры шаблонов)"}
                    <div className="pl-2 pr-2">
                        <ProgressBar now="65" label={"65%"}/>
                    </div>
                    <small className="text-muted">
                        {"файлов загруженных / всего: 3 / 12"}
                    </small>
                </Card>
                <Card className="mb-3">
                    {"1052 - AO Vladimir (задача: фильтрация файлов, это только примеры шаблонов)"}
                    <div className="pl-2 pr-2">
                        <ProgressBar now="78" label={"132/245"}/>
                    </div>
                    <small className="text-muted">
                        {"файлов найдено / обработано / всего: 13 / 132 / 245 (найдено: 1 433 554 байт, всего: 355 485 866 байт)"}
                    </small>
                </Card>
                <br/>
                {this.createFiltrationWidget.call(this)}
            </React.Fragment>
        );
    }
}

CreateBodyDynamics.propTypes = {
    socketIo: PropTypes.object.isRequired,
};