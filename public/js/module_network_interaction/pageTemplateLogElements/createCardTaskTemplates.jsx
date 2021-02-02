import React from "react";
import { Badge, Col, Row } from "react-bootstrap";
import ButtonUI from "@material-ui/core/Button";
import Card from "@material-ui/core/Card";
import CardActions from "@material-ui/core/CardActions";
import CardContent from "@material-ui/core/CardContent";
import Typography from "@material-ui/core/Typography";
import PropTypes from "prop-types";

import CreateListNetworkParameters from "./createListNetworkParameters.jsx";

export default function CreateCardTaskTemplates(props){
    const formatter = Intl.DateTimeFormat("ru-Ru", {
        timeZone: "Europe/Moscow",
        day: "numeric",
        month: "numeric",
        year: "numeric",
        hour: "numeric",
        minute: "numeric",
    });

    let daysOfWeek = [];
    let textColor = "text-primary";

    for(let shortName in props.templatesInformation.dateTimeTrigger.weekday){
        daysOfWeek.push(props.templatesInformation.dateTimeTrigger.weekday[shortName]);
    }

    let showParametersFiltration = () => {
        if(props.templatesInformation.taskType === "telemetry"){
            return null;
        }

        let netProto = (props.templatesInformation.taskParameters.filtration.networkProtocol === "any") ? "любой" : props.templatesInformation.taskParameters.filtration.networkProtocol;

        return (
            <React.Fragment>
                <Row>
                    <Col md={12} className="text-left">
                        <Typography variant="subtitle1" color="textSecondary">
                        Опции для фильтрации:
                        </Typography>
                    </Col>
                </Row>
                <Row>
                    <Col md={12} className="text-left">
                        <Typography variant="subtitle1" color="textSecondary">
                            время начала:&nbsp; 
                            <strong>{formatter.format(props.templatesInformation.taskParameters.filtration.start_date)}</strong>
                            , окончания:&nbsp; 
                            <strong>{formatter.format(props.templatesInformation.taskParameters.filtration.end_date)}</strong>
                            , сетевой протокол:&nbsp; 
                            <strong>{netProto}</strong>
                        </Typography>
                    </Col>
                </Row>
                <Row>
                    <Col md={4} className="text-center">
                        <Typography variant="subtitle1" color="textSecondary">ip адреса</Typography>
                    </Col>
                    <Col md={4} className="text-center">
                        <Typography variant="subtitle1" color="textSecondary">диапазоны сетей</Typography>
                    </Col>
                    <Col md={4} className="text-center">
                        <Typography variant="subtitle1" color="textSecondary">сетевые порты</Typography>
                    </Col>
                </Row>
                <Row>
                    <Col md={4} className="text-center">
                        <CreateListNetworkParameters 
                            type="ip"
                            inputValue={props.templatesInformation.taskParameters.filtration.inputValue} />
                    </Col>
                    <Col md={4} className="text-center">
                        <CreateListNetworkParameters 
                            type="nw"
                            inputValue={props.templatesInformation.taskParameters.filtration.inputValue} />
                    </Col>
                    <Col md={4} className="text-center">
                        <CreateListNetworkParameters 
                            type="pt"
                            inputValue={props.templatesInformation.taskParameters.filtration.inputValue} />
                    </Col>
                </Row>
            </React.Fragment>
        );
    };

    return (
        <Card>
            <CardContent>
                <Row>
                    <Col md={12} className="text-left">
                        <Typography variant="subtitle1" color="textSecondary">
                        Шаблон добавлен <strong>{formatter.format(props.templatesInformation.timeCreation)}</strong>, пользователем <strong>{props.templatesInformation.userName}</strong>.
                        </Typography>
                    </Col>
                </Row>
                <Row>
                    <Col md={4} className="text-right">
                        <Typography variant="subtitle1" color="textSecondary">тип шаблона:</Typography>
                    </Col>
                    <Col md={8} className="text-left">{(props.templatesInformation.taskType === "telemetry") ? 
                        <Badge variant="dark">{"телеметрия"}</Badge>
                        : 
                        <Badge variant="primary">{"фильтрация"}</Badge>}</Col>
                </Row>
                <Row>
                    <Col md={4} className="text-right">
                        <Typography variant="subtitle1" color="textSecondary">дни недели:</Typography>
                    </Col>
                    <Col md={8} className="text-left">{(()=>{
                        let i = 0;
                        let num = daysOfWeek.length;
                        let comma = ", ";
                        
                        return daysOfWeek.map((item) => {
                            if(item === "суббота" || item === "воскресенье"){
                                textColor = "text-danger";
                            } else {
                                textColor = "text-primary";
                            }

                            return (num > ++i) ? <span key={`key_day_of_week_${item}`} className={textColor}>{item+comma}</span> : <span key={`key_day_of_week_${item}`} className={textColor}>{item}</span>;
                        });
                    })()}</Col>
                </Row>
                <Row>
                    <Col md={4} className="text-right">
                        <Typography variant="subtitle1" color="textSecondary">время выполнения:</Typography>                        
                    </Col>
                    <Col md={8} className="text-left">
                        {(() => {
                            let hour = props.templatesInformation.dateTimeTrigger.hour;
                            let minute = props.templatesInformation.dateTimeTrigger.minutes;

                            return ((hour < 10) ? "0"+hour : hour)+":"+((minute < 10) ? "0"+minute : minute);
                        })()}
                    </Col>
                </Row>
                <Row>
                    <Col md={4} className="text-right">
                        <Typography variant="subtitle1" color="textSecondary">список источников для выполнения:</Typography>                        
                    </Col>
                    <Col md={8} className="text-left">
                        {(() => {
                            if(props.templatesInformation.listSourceID.length === 0){
                                return <h5><Badge variant="light">{"на всех источниках"}</Badge></h5>;
                            }

                            return props.templatesInformation.listSourceID.map((item) => {
                                return <Badge pill variant="secondary" className="mr-1" key={`key_sid_${item}`}>{item}</Badge>;
                            });
                        })()}
                    </Col>
                </Row>
                {showParametersFiltration()}
            </CardContent>
            <CardActions>
                <ButtonUI 
                    size="small"
                    onClick={props.handlerDeteteCard}>
                    удалить
                </ButtonUI>
            </CardActions>
        </Card>
    );
}

CreateCardTaskTemplates.propTypes = {
    templatesInformation: PropTypes.object.isRequired,
    handlerDeteteCard: PropTypes.func.isRequired,
};