import React from "react";
import { Col, Row } from "react-bootstrap";
import Typography from "@material-ui/core/Typography";
import PropTypes from "prop-types";

export default function CreateInformationTimeFiltrationInterval(props){
    let hoursName = "часа",
        minHour = "час",
        min = props.minHour,
        max = props.maxHour,
        currentTime = max - min,
        timeTriggerHours = props.timeTrigger.getHours(),
        timeTriggerMinutes = props.timeTrigger.getMinutes(),
        timeBegin = +props.timeTrigger - ((min + currentTime) * 3600000),
        timeEnd = +props.timeTrigger - (min  * 3600000),
        tbh = (new Date(timeBegin)).getHours(),
        tbm = (new Date(timeBegin)).getMinutes(),
        beginString = `${(tbh < 10) ? "0"+tbh: tbh}:${(tbm < 10) ? "0"+tbm: tbm}`,
        teh = (new Date(timeEnd)).getHours(),
        tem = (new Date(timeEnd)).getMinutes(),
        endString = `${(teh < 10) ? "0"+teh: teh}:${(tem < 10) ? "0"+tem: tem}`;

    if((currentTime >= 2 && currentTime <= 20) || (currentTime >= 22) || (currentTime === 0)){
        hoursName = "часов";
    }

    if((min >= 2 && min <= 4) || (min >= 22)){
        minHour = "часа";
    }

    if((min >= 5 && min <= 20) || (min === 0)){
        minHour = "часов";
    }

    let isColorRed = "";
    if((beginString === endString) || (currentTime === 0)){
        isColorRed = "text-danger";
    }

    let startTimerDay = "текущих суток";
    if(tbh >= timeTriggerHours){
        startTimerDay = "прошедших суток";
    }

    let endTimerDay = "текущих суток";
    if(teh > timeTriggerHours){
        endTimerDay = "прошедших суток";
    }

    return (
        <Row>
            <Col md={12} className="text-left">
                <Typography variant="subtitle1" color="textSecondary">
                        Задан временной диапазон в интервале <strong className={isColorRed}>{currentTime}</strong> {hoursName}, начиная с <strong className={isColorRed}>{beginString}</strong> {startTimerDay}, по <strong className={isColorRed}>{endString}</strong> {endTimerDay}.
                        Контрольная точка запуска задачи установлена на <strong>{`${(timeTriggerHours < 10) ? "0"+timeTriggerHours: timeTriggerHours}:${(timeTriggerMinutes < 10) ? "0"+timeTriggerMinutes: timeTriggerMinutes}`}</strong>.
                        Смещение в прошлое от начала контрольной точки <strong>{min}</strong> {minHour}.
                </Typography>
            </Col>
        </Row>
    );
}

CreateInformationTimeFiltrationInterval.propTypes = {
    minHour: PropTypes.number.isRequired,
    maxHour: PropTypes.number.isRequired,
    timeTrigger: PropTypes.object.isRequired,
};
