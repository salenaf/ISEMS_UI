import React from "react";
import { Col, Row } from "react-bootstrap";
import Radio from "@material-ui/core/Radio";
import Checkbox from "@material-ui/core/Checkbox";
import FormGroup from "@material-ui/core/FormGroup";
import RadioGroup from "@material-ui/core/RadioGroup";
import FormControlLabelUI from "@material-ui/core/FormControlLabel";
import { TimePicker, MuiPickersUtilsProvider } from "material-ui-pickers";
import DateFnsUtils from "dateIoFnsUtils";

import PropTypes from "prop-types";

function CreateTimePicker(props){
    return (
        <MuiPickersUtilsProvider utils={DateFnsUtils}>
            <TimePicker
                clearable
                ampm={false}
                label={props.label}
                value={props.selectedDate}
                onChange={props.handleDateChange}
            />
        </MuiPickersUtilsProvider>
    );
}

CreateTimePicker.propTypes = {
    label: PropTypes.string.isRequired,
    selectedDate: PropTypes.object.isRequired,
    handleDateChange: PropTypes.func.isRequired,
};

export default function CreateFormControlChangeTime(props){
    let createListDays = () => {
        let listChecbox = [];

        for(let dayOfWeek in props.listSelectedDays){
            let checkboxColor = (dayOfWeek === "Sat" || dayOfWeek === "Sun") ? "secondary": "primary";

            listChecbox.push(<FormControlLabelUI
                key={`checkbox_${dayOfWeek}`}
                className="mb-n3"
                value={dayOfWeek}
                control={
                    <Checkbox 
                        checked={props.listSelectedDays[dayOfWeek].checked} 
                        onChange={props.handlerChangeCheckboxDayOfWeek} 
                        name={dayOfWeek}
                        color={checkboxColor} />
                }
                label={props.listSelectedDays[dayOfWeek].name} />);
        }

        return (
            <FormGroup>{listChecbox}</FormGroup>
        );
    };

    return (
        <Row>
            <Col md={4}>
                <CreateTimePicker
                    label="время выполнения"
                    selectedDate={props.timeTrigger} 
                    handleDateChange={props.handlerChangeTimeTrigger} />
            </Col>
            <Col md={4}>
                <RadioGroup 
                    aria-label="gender" 
                    name="templateTime" 
                    value={props.checkSelectedType} 
                    onChange={props.handlerChangeTemplateTimeRadioType}>
                    <FormControlLabelUI className="mb-n1" value="no_days" control={<Radio color="primary" size="small" />} label="дни не выбраны" />
                    <FormControlLabelUI className="mb-n1" value="every_day" control={<Radio color="primary" size="small" />} label="каждый день" />
                    <FormControlLabelUI className="mb-n1" value="working_days_only" control={<Radio color="primary" size="small" />} label="только рабочие дни" />
                    <FormControlLabelUI className="mb-n1" value="weekends_only" control={<Radio color="primary" size="small" />} label="только выходные" />
                </RadioGroup>
            </Col>
            <Col md={4}>
                {createListDays()}
            </Col>
        </Row>
    );
}

CreateFormControlChangeTime.propTypes = {
    timeTrigger: PropTypes.object.isRequired,
    listSelectedDays: PropTypes.object.isRequired,
    checkSelectedType: PropTypes.string.isRequired,
    handlerChangeTimeTrigger: PropTypes.func.isRequired,
    handlerChangeCheckboxDayOfWeek: PropTypes.func.isRequired,
    handlerChangeTemplateTimeRadioType: PropTypes.func.isRequired,
};