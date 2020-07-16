import React from "react";
import { Card } from "react-bootstrap";
import PropTypes from "prop-types";

export default class CreatingWidgets extends React.Component {
    constructor(props){
        super(props);

        this.state = {
            filtration: new Set(),
            download: new Set(),
        };

        this.handlerEvents.call(this);
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
                } else {
                    objCopy.download.add(msg.options.taskID);
                }

                this.setState(objCopy);
            }
        });
    }

    render(){
        return (
            <div className="row d-flex justify-content-center">
                <Card className="ml-3" border="success" style={{ width: "10rem" }}>
                    <small>источников</small>
                    <span className="my-n2 text-success">{this.props.widgets.numConnect}</span>
                    <small className="text-muted">подключено</small>
                </Card>
                <Card className="ml-3" border="danger" style={{ width: "10rem" }}>
                    <small>источников</small>
                    <span className="my-n2 text-danger">{this.props.widgets.numDisconnect}</span>
                    <small className="text-muted">не доступно</small>
                </Card>
                <Card className="ml-3" border="dark" style={{ width: "10rem" }}>
                    <small>фильтрация</small>
                    <span className="my-n2">{this.state.filtration.size}</span>
                    <small className="text-muted">выполняется</small>
                </Card>
                <Card className="ml-3" border="info" style={{ width: "13rem" }}>
                    <small>загрузка файлов</small>
                    <span className="my-n2 text-info">{this.state.download.size} / {this.props.widgets.numTasksNotDownloadFiles}</span>
                    <small className="text-muted"> выполняется / доступна</small>
                </Card>
                <Card className="ml-3" border="info" style={{ width: "13rem" }}>
                    <small>загруженные файлы</small>
                    <span className="my-n2 text-info">0</span>
                    <small className="text-muted">нерассмотренны</small>
                </Card>
            </div>
        );
    }
}

CreatingWidgets.propTypes = {
    widgets: PropTypes.object.isRequired,
    socketIo: PropTypes.object.isRequired,
};