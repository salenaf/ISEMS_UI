import React from "react";
import ReactDOM from "react-dom";
import { Button, Col, Row, OverlayTrigger, Tooltip } from "react-bootstrap";
import PropTypes from "prop-types";

class CreatePageStatisticsAndAnalyticsDetalTask extends React.Component {
    constructor(props){
        super(props);

        this.state = {
            disabledButtonCloseTask: "disabled",
        };

        this.formatterDate = this.formatterDate.bind(this);
        this.buttonBackArrow = this.buttonBackArrow.bind(this);
        this.handlerCloseTask = this.handlerCloseTask.bind(this);

        this.handlerEvents.call(this);
        this.getInformationAboutTask.call(this);
    }

    handlerEvents(){
        this.props.socketIo.on("СОБЫТИЕ", (data) => {
            console.log(data);
        /*
        здесь получаем аналитическую информацию о задаче и загруженном
        сетевом трафике и проверяем выгружались ли файлы и права пользователя
        на изменение статуса задачи на 'закрытая'

            изменить state.disabledButtonCloseTask
        this.props.listItems.userPermissions.management_uploaded_files.element_settings.status_change.status
        */
        });
    }

    getInformationAboutTask(){
        this.props.socketIo.emit("network interaction: get analytics information about task id", {
            arguments: { taskID: this.props.listItems.urlQueryParameters.taskID } 
        });
    }

    handlerCloseTask(){
        console.log("func 'handlerCloseTask', START...");

        /**
         * 
         * Не доделал обработчик запроса на закрытие задачи
         * в модуле ISEMS-NIH это уже реализовано,
         * нет в backend ISEMS-UI
         * 
         * При этом если задача еще не завершена то необходимо предоставить
         * пользователю сделать отметку с поеснением причины завершения, однако
         * данное действие не должно быть обязательным.
         * 
         * Если мы просматриваем информацию о задаче, которая уже была закрыта
         * необходимо вывести информацию О ТОМ КТО ЗАВЕРШИЛ задачу и ОПИСАНИЕ
         * ПРИЧИНЫ ЗАВЕРЩЕНИЯ (думаю если причины завершения нет в интерфейсе нужно 
         * писать какую нибудь стандартную фразу типа "выполнен стандартный анализ")
         * 
         */
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
                            &nbsp;<i>(задача создана {this.formatterDate().format(this.props.listItems.urlQueryParameters.taskBeginTime)})</i>
                            </Col>
                        </Row>
                    </Col>
                    <Col md={2} className="text-right mt-1">
                        <Button
                            className="mx-1"
                            size="sm"
                            variant="outline-danger"
                            onClick={this.handlerCloseTask}
                            disabled={this.state.disabledButtonCloseTask} >
                            закрыть задачу
                        </Button>
                    </Col>
                </Row>
                <Row>
                    <Col md={12} className="mt-4">
                        основная информация
                    </Col>
                </Row>
            </React.Fragment>
        );
    }
}

/**
создана ${this.formatterDate().format(this.props.listItems.urlQueryParameters.taskBeginTime)}
 */

CreatePageStatisticsAndAnalyticsDetalTask.propTypes = {
    socketIo: PropTypes.object.isRequired,
    listItems: PropTypes.object.isRequired,
};

ReactDOM.render(<CreatePageStatisticsAndAnalyticsDetalTask
    socketIo={socket}
    listItems={receivedFromServer} />, document.getElementById("main-page-content"));
