import React from "react";
import { Col, Row } from "react-bootstrap";
import { DateTimePicker, MuiPickersUtilsProvider } from "material-ui-pickers";
import DateFnsUtils from "dateIoFnsUtils";
import PropTypes from "prop-types";

function CreateDateTimePicker(props) {
    return (
        <Row>
            <Col sm={6}>
                <MuiPickersUtilsProvider utils={DateFnsUtils}>
                    <DateTimePicker
                        variant="inline"
                        ampm={false}
                        label="начальное время"
                        value={props.currentDateTimeStart}
                        minDate={new Date("2000-01-01")}
                        maxDate={new Date()}
                        onChange={props.handlerChangeDateTimeStart}
                        format="dd.MM.yyyy HH:mm"
                    />
                </MuiPickersUtilsProvider>
            </Col>
            <Col sm={6} className="text-right">
                <MuiPickersUtilsProvider utils={DateFnsUtils}>
                    <DateTimePicker
                        variant="inline"
                        ampm={false} //12/24 часа
                        label="конечное время"
                        value={props.currentDateTimeEnd}
                        minDate={new Date("2000-01-01")}
                        maxDate={new Date()}
                        onChange={props.handlerChangeDateTimeEnd}
                        format="dd.MM.yyyy HH:mm"
                    />
                </MuiPickersUtilsProvider>
            </Col>
        </Row>
    );
}

CreateDateTimePicker.propTypes = {
    currentDateTimeStart: PropTypes.object,
    currentDateTimeEnd: PropTypes.object,
    handlerChangeDateTimeStart: PropTypes.func,
    handlerChangeDateTimeEnd: PropTypes.func,
};

export default CreateDateTimePicker;




