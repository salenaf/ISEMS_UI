import React from "react";
import { Col, Row } from "react-bootstrap";
import Typography from "@material-ui/core/Typography";
import PropTypes from "prop-types";

export default function CreateInformationTimeFiltrationInterval(props){
    let hoursName = "часа",
        minHour = "час",
        min = props.parametersFiltration.dateTime.minHour,
        max = props.parametersFiltration.dateTime.maxHour,
        currentTime = max - min,
        timeTriggerHours = props.templateParameters.templateTime.timeTrigger.getHours(),
        timeTriggerMinutes = props.templateParameters.templateTime.timeTrigger.getMinutes(),
        timeBegin = +props.templateParameters.templateTime.timeTrigger - ((props.parametersFiltration.dateTime.minHour + currentTime) * 3600000),
        timeEnd = +props.templateParameters.templateTime.timeTrigger - (props.parametersFiltration.dateTime.minHour  * 3600000),
        tbh = (new Date(timeBegin)).getHours(),
        tbm = (new Date(timeBegin)).getMinutes(),
        beginString = `${(tbh < 10) ? "0"+tbh: tbh}:${(tbm < 10) ? "0"+tbm: tbm}`,
        teh = (new Date(timeEnd)).getHours(),
        tem = (new Date(timeEnd)).getMinutes(),
        endString = `${(teh < 10) ? "0"+teh: teh}:${(tem < 10) ? "0"+tem: tem}`;

    if((currentTime >= 2 && currentTime <= 20) || (currentTime >= 22)){
        hoursName = "часов";
    }

    if((min >= 2 && min <= 4) || (min >= 22)){
        minHour = "часа";
    }

    if(min >= 5 && min <= 20){
        minHour = "часов";
    }

    return (
        <React.Fragment>
            <Row>
                <Col md={12} className="text-left">
                    <Typography variant="subtitle1" color="textSecondary">
                        выбран временной диапазон в интервале <strong>{currentTime}</strong> {hoursName}, начиная с <strong>{beginString}</strong> по <strong>{endString}</strong>
                    </Typography>
                </Col>
            </Row>
            <Row>
                <Col md={12} className="text-left">
                    <Typography variant="subtitle1" color="textSecondary">
                        контрольная точка запуска задачи установлена на <strong>{`${(timeTriggerHours < 10) ? "0"+timeTriggerHours: timeTriggerHours}:${(timeTriggerMinutes < 10) ? "0"+timeTriggerMinutes: timeTriggerMinutes}`}</strong>
                    </Typography>
                </Col>
            </Row>
            <Row>
                <Col md={12} className="text-left">
                    <Typography variant="subtitle1" color="textSecondary">
                        смещение в прошлое, от начала контрольной точки, составляет <strong>{min}</strong> {minHour}
                    </Typography>
                </Col>
            </Row>
        </React.Fragment>
    );
}

CreateInformationTimeFiltrationInterval.propTypes = {
    templateParameters: PropTypes.object.isRequired,
    parametersFiltration: PropTypes.object.isRequired,    
};