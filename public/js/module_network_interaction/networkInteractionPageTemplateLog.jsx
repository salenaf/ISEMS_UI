import React from "react";
import ReactDOM from "react-dom";
import { Button, Col, Row } from "react-bootstrap";
import { makeStyles } from "@material-ui/core/styles";
import { blue } from "@material-ui/core/colors";
import Card from "@material-ui/core/Card";
import CardActions from "@material-ui/core/CardActions";
import CardContent from "@material-ui/core/CardContent";
import Radio from "@material-ui/core/Radio";
import ButtonUI from "@material-ui/core/Button";
import Checkbox from "@material-ui/core/Checkbox";
import FormGroup from "@material-ui/core/FormGroup";
import FormLabel from "@material-ui/core/FormLabel";
import RadioGroup from "@material-ui/core/RadioGroup";
import FormControl from "@material-ui/core/FormControl";
import FormControlLabel from "@material-ui/core/FormControlLabel";
import { TimePicker, MuiPickersUtilsProvider } from "material-ui-pickers";
import DateFnsUtils from "dateIoFnsUtils";
import PropTypes from "prop-types";

import CreateSteppersTemplateLog from "../commons/createSteppersTemplateLog.jsx";
//import { propTypes } from "react-bootstrap/esm/Image";

const useStyles = makeStyles((theme) => ({
    root: {
        display: "flex",
        alignItems: "center",
    },
    wrapper: {
        margin: theme.spacing(1),
        position: "relative",
    },
    buttonProgress: {
        color: blue[500],
        position: "absolute",
        top: "50%",
        left: "50%",
        marginTop: -12,
        marginLeft: -12,
    },
}));

/*function CreateCard(props){
    const classes = useStyles();

    return (
        <Crad>
            <CardContent>
            </CardContent>
        </Crad>
    );
}

CreateCart.PropTypes = {

};*/

function CreateTimePicker(props){
    return (
        <MuiPickersUtilsProvider utils={DateFnsUtils}>
            <TimePicker
                clearable
                ampm={false}
                label="24 hours"
                value={props.selectedDate}
                onChange={props.handleDateChange}
            />
        </MuiPickersUtilsProvider>
    );
}

CreateTimePicker.propTypes = {
    selectedDate: PropTypes.object.isRequired,
    handleDateChange: PropTypes.func.isRequired,
};

function CreateButtons(props){
    const classes = useStyles();

    let createButtonBack = () => {
        return (
            <ButtonUI 
                onClick={props.handlerButtonBack} 
                disabled={props.numberSteppers === 0}>
                назад
            </ButtonUI>
        );
    };

    let createButtonNext = () => {
        let isFinish = false;

        if(props.templateParameters.templateType === "telemetry" && props.numberSteppers >= 3){
            isFinish = true;
        }

        if(props.numberSteppers === 4){
            isFinish = true;
        }

        if(isFinish){
            return (
                <ButtonUI 
                    size="small"
                    color="primary" 
                    onClick={props.handlerButtonFinish}>
                    завершить
                </ButtonUI>
            );
        } else {
            return (
                <ButtonUI 
                    size="small"
                    color="primary" 
                    onClick={props.handlerButtonNext}>
                    вперед
                </ButtonUI>
            );
        }
    };

    return (
        <Row>
            <Col md={12} className="text-left ml-1">
                {createButtonBack()}
                {createButtonNext()}
                <ButtonUI 
                    size="small"
                    color="secondary"
                    onClick={props.handlerButtonCancel}>
                    отменить
                </ButtonUI>
            </Col>
        </Row>
    );
}

CreateButtons.propTypes = {
    numberSteppers: PropTypes.number.isRequired,
    templateParameters: PropTypes.object.isRequired,
    handlerButtonBack: PropTypes.func.isRequired,
    handlerButtonNext: PropTypes.func.isRequired,
    handlerButtonCancel: PropTypes.func.isRequired,
    handlerButtonFinish: PropTypes.func.isRequired,
};

class CreatePageTemplateLog extends React.Component {
    constructor(props){
        super(props);

        this.state = {
            showForm: false,
            showButtonAddTask: true,
            steppers: ["тип задачи" , "время", "источники", "параметры", "завершить"],
            numberSteppers: 0,
            stepsComplete: [],
            stepsError: [],
            templateParameters: {
                templateType: "telemetry",
                templateTime: {
                    checkSelectedType: "no_days",
                    timeTrigger: new Date,
                    listSelectedDays: {
                        Mon: { checked: false, name: "понедельник" },
                        Tue: { checked: false, name: "вторник" },
                        Wed: { checked: false, name: "среда" },
                        Thu: { checked: false, name: "четверг" },
                        Fri: { checked: false, name: "пятница" },
                        Sat: { checked: false, name: "суббота" },
                        Sun: { checked: false, name: "воскресенье" },
                    },
                },
            },
        };

        this.handlerButtonBack = this.handlerButtonBack.bind(this);
        this.handlerButtonNext = this.handlerButtonNext.bind(this);   
        this.handlerButtonCancel = this.handlerButtonCancel.bind(this);
        this.handlerButtonFinish = this.handlerButtonFinish.bind(this);
        this.handlerButtonAddTask = this.handlerButtonAddTask.bind(this);
    }

    handlerButtonAddTask(){
        this.setState({ 
            showForm: true,
            showButtonAddTask: false,
        });
    }

    handlerButtonBack(){
        
        console.log(`func 'handlerButtonBack', this.state.numberSteppers = ${this.state.numberSteppers}`);

        if(this.state.stepsError.includes(this.state.numberSteppers)){
            let stepsError = this.state.stepsError;
            stepsError.splice(this.state.numberSteppers - 1, 1);

            this.setState({ stepsError: stepsError });
        }

        if(this.state.numberSteppers === 0){
            return;
        }

        let numberSteppers = this.state.numberSteppers;
        let stepsComplete = this.state.stepsComplete;

        if(this.state.templateParameters.templateType === "telemetry"){
            if(numberSteppers === 4){
                stepsComplete.splice(numberSteppers - 2, 2);
                this.setState({ 
                    stepsComplete: stepsComplete,
                    numberSteppers: numberSteppers - 2 
                });    
            } else {
                stepsComplete.pop();
                this.setState({ 
                    stepsComplete: stepsComplete,
                    numberSteppers: --numberSteppers 
                });    
            }
        } else {
            stepsComplete.pop();
            this.setState({
                stepsComplete: stepsComplete,
                numberSteppers: --numberSteppers 
            });
        }
    }

    handlerButtonNext(){
        if(this.state.numberSteppers === 4){
            return;
        }

        let numberSteppers = this.state.numberSteppers;
        let stepsComplete = this.state.stepsComplete;

        if(this.state.templateParameters.templateType === "telemetry" && numberSteppers === 2){
            stepsComplete.push(2);
            this.setState({ 
                stepsComplete: stepsComplete,
                numberSteppers: 4 
            });

            return;
        }

        stepsComplete.push(numberSteppers);
        this.setState({ 
            stepsComplete: stepsComplete,
            numberSteppers: ++numberSteppers 
        });

        //делаем валидацию некоторых форм
        this.handlerCheckForm.call(this);
    }

    handlerButtonFinish(){
        console.log("func 'handlerButtonFinish', START");
        console.log("выполняем обработку запроса на добавление шаблона");
    
        let numberSteppers = this.state.numberSteppers;
        if(this.state.templateParameters.templateType === "telemetry" && numberSteppers === 2){
            this.setState({ numberSteppers: 4 });

            return;
        }
    }

    handlerButtonCancel(){
        console.log("func 'handlerButtonCancel'");
    }

    handlerCheckForm(){
        //тут делаем валидацию НЕКОТРЫХ форм
        //пока для теста выберем форму с временем

        if(this.state.numberSteppers === 1){
            let stepsError = this.state.stepsError;
            stepsError.push(1);

            this.setState({ stepsError: stepsError });
        }
    }

    handleChangeTemplateType(event){
        let templateParameters = this.state.templateParameters;
        templateParameters.templateType = event.target.value;

        this.setState({ templateParameters: templateParameters });
    }

    handleChangeTemplateTimeRadioType(event){
        const value = event.target.value;
        let templateParameters = this.state.templateParameters;
        let cleanAllChecked = () => {
            for(let dayName in templateParameters.templateTime.listSelectedDays){
                templateParameters.templateTime.listSelectedDays[dayName].checked = false;
            }
        };

        templateParameters.templateTime.checkSelectedType = value;

        switch(value){
        case "no_days":
            cleanAllChecked();

            break;

        case "every_day":
            for(let dayName in templateParameters.templateTime.listSelectedDays){
                templateParameters.templateTime.listSelectedDays[dayName].checked = true;
            }

            break;

        case "working_days_only":
            for(let dayName in templateParameters.templateTime.listSelectedDays){
                if(dayName === "Sat" || dayName === "Sun"){
                    templateParameters.templateTime.listSelectedDays[dayName].checked = false;
                } else {
                    templateParameters.templateTime.listSelectedDays[dayName].checked = true;
                }
            }    
        
            break;

        case "weekends_only":
            cleanAllChecked();

            templateParameters.templateTime.listSelectedDays.Sat.checked = true;
            templateParameters.templateTime.listSelectedDays.Sun.checked = true;

            break;
        }

        this.setState({ templateParameters: templateParameters });
    }

    handleChangeCheckboxdayOfWeek(event){
        console.log("func 'handleChangeCheckboxdayOfWeek', START...");
        console.log(event.target.value);

        /**
templateParameters: {
                templateType: "telemetry",
                templateTime: {
                    checkSelectedType: "every_day",
                    listSelectedDays: {
                        Mon: { checked: false, name: "понедельник" },
                        Tue: { checked: false, name: "вторник" },
                        Wed: { checked: false, name: "среда" },
                        Thu: { checked: false, name: "четверг" },
                        Fri: { checked: false, name: "пятница" },
                        Sat: { checked: false, name: "суббота" },
                        Sun: { checked: false, name: "воскресенье" },
                    },
                },
            },
 */

    }

    handlerChangeTimeTrigger(date){
        console.log("func 'handlerChangeTimeTrigger'");
        console.log(date);

        let objCopy = Object.assign({}, this.state.templateParameters);
        objCopy.templateTime.timeTrigger = date;
        this.setState({ templateParameters: objCopy });
    }

    createTemplateList(){
        if(this.state.showForm){
            return;
        }

        return (
            <Row>
                <Col md={12}>
        здесь будет список шаблонов
        с кратким описанием, при этом
        будет тип задачи (телеметрия, фильтрация)
                    <ul>
                        <li>Выбор типа шаблона</li>
                        <li>Выбор времени и дней недели ( все, только будни, только выходные, перечисляем дни недели)</li>
                        <li>сипоск источников или все</li>
                        <li>для телеметрии все, для фильтрации еще параметры</li>
                    </ul>
                </Col>
            </Row>
        );
    }

    createBottonAddTask(){
        if(!this.state.showButtonAddTask){
            return;
        }

        return (
            <Row>
                <Col md={12} className="text-left">
                    <Button 
                        size="sm"
                        variant="outline-primary" 
                        onClick={this.handlerButtonAddTask}>
                            добавить шаблон
                    </Button>
                </Col>
            </Row>
        );
    }

    createFormControlChangeTime(){
        let createListDays = () => {
            let listChecbox = [];
            let listSelectedDays = this.state.templateParameters.templateTime.listSelectedDays;

            for(let dayOfWeek in listSelectedDays){
                let checkboxColor = (dayOfWeek === "Sat" || dayOfWeek === "Sun") ? "secondary": "primary";

                listChecbox.push(<FormControlLabel
                    key={`checkbox_${dayOfWeek}`}
                    className="mb-n3"
                    control={
                        <Checkbox 
                            checked={listSelectedDays[dayOfWeek].checked} 
                            onChange={this.handleChangeCheckboxdayOfWeek} 
                            name={dayOfWeek}
                            color={checkboxColor} />
                    }
                    label={listSelectedDays[dayOfWeek].name} />);
            }

            return (
                <FormGroup>{listChecbox}</FormGroup>
            );
        };

        return (
            <Row>
                <Col md={4}>
                    <RadioGroup 
                        aria-label="gender" 
                        name="templateTime" 
                        value={this.state.templateParameters.templateTime.checkSelectedType} 
                        onChange={this.handleChangeTemplateTimeRadioType.bind(this)}>
                        <FormControlLabel className="mb-n3" value="no_days" control={<Radio color="primary" size="small" />} label="дни не выбраны" />
                        <FormControlLabel className="mb-n3" value="every_day" control={<Radio color="primary" size="small" />} label="каждый день" />
                        <FormControlLabel className="mb-n3" value="working_days_only" control={<Radio color="primary" size="small" />} label="только рабочие дни" />
                        <FormControlLabel className="mb-n3" value="weekends_only" control={<Radio color="primary" size="small" />} label="только выходные" />
                    </RadioGroup>
                </Col>
                <Col md={4}>
                    {createListDays()}
                </Col>
                <Col md={4}>
                    <CreateTimePicker
                        selectedDate={this.state.templateParameters.templateTime.timeTrigger} 
                        handleDateChange={this.handlerChangeTimeTrigger.bind(this)} />
                </Col>
            </Row>
        );
    }

    createForm(){       
        switch(this.state.numberSteppers){
        case 0:
            return (
                <Row>
                    <Col md={12} className="text-center">
                        <RadioGroup 
                            aria-label="gender" 
                            name="templateType" 
                            value={this.state.templateParameters.templateType} 
                            onChange={this.handleChangeTemplateType.bind(this)}>
                            <FormControlLabel className="mb-n2" value="telemetry" control={<Radio color="primary" size="small" />} label="телеметрия" />
                            <FormControlLabel value="filtration" disabled control={<Radio color="primary" size="small" />} label="фильтрация" />
                        </RadioGroup>
                    </Col>
                </Row>
            );

        case 1:
            return this.createFormControlChangeTime.call(this);

        case 2:
            return (
                <FormControl component="fieldset">
                    <FormLabel component="legend">Выбор источника</FormLabel>
                </FormControl>
            );

        case 3:
            return (
                <FormControl component="fieldset">
                    <FormLabel component="legend">Выбор параметров</FormLabel>
                </FormControl>
            );
        }
    }

    createButtons(){
        let createButtonBack = () => {
            return (
                <ButtonUI 
                    onClick={this.handlerButtonBack} 
                    disabled={this.state.numberSteppers === 0}>
                    назад
                </ButtonUI>
            );
        };

        let createButtonNext = () => {
            let isFinish = false;

            if(this.state.templateParameters.templateType === "telemetry" && this.state.numberSteppers >= 3){
                isFinish = true;
            }

            if(this.state.numberSteppers === 4){
                isFinish = true;
            }

            if(isFinish){
                return (
                    <ButtonUI 
                        size="small"
                        color="primary" 
                        onClick={this.handlerButtonFinish}>
                        завершить
                    </ButtonUI>
                );
            } else {
                return (
                    <ButtonUI 
                        size="small"
                        color="primary" 
                        onClick={this.handlerButtonNext}>
                        вперед
                    </ButtonUI>
                );
            }
        };

        return (
            <Row>
                <Col md={12} className="text-left ml-1">
                    {createButtonBack()}
                    {createButtonNext()}
                    <ButtonUI 
                        size="small"
                        color="secondary"
                        onClick={this.handlerButtonCancel}>
                        отменить
                    </ButtonUI>
                </Col>
            </Row>
        );
    }

    render(){
        return (
            <React.Fragment>
                <Row>
                    <Col md={12}>
                        <CreateSteppersTemplateLog 
                            show={this.state.showForm}
                            steppers={this.state.steppers}
                            activeStep={this.state.numberSteppers}
                            stepsError={this.state.stepsError}
                            stepsComplete={this.state.stepsComplete} />
                    </Col>
                </Row>
                {(this.state.showForm) &&
                    <Row>
                        <Col md={1}></Col>
                        <Col md={10}>
                            <Card>
                                <CardContent>
                                    {this.createForm.call(this)}
                                </CardContent>
                                <CardActions>
                                    {/*this.createButtons.call(this)*/}
                                    <CreateButtons 
                                        numberSteppers={this.state.numberSteppers}
                                        templateParameters={this.state.templateParameters}
                                        handlerButtonBack={this.handlerButtonBack}
                                        handlerButtonNext={this.handlerButtonNext}
                                        handlerButtonCancel={this.handlerButtonCancel}
                                        handlerButtonFinish={this.handlerButtonFinish} />
                                </CardActions>                
                            </Card>
                        </Col>
                        <Col md={1}></Col>
                    </Row>}
                {this.createBottonAddTask.call(this)}
                {this.createTemplateList.call(this)}
            </React.Fragment>
        );
    }
}

CreatePageTemplateLog.propTypes = {
    socketIo: PropTypes.object.isRequired,
    listItems: PropTypes.object.isRequired,
}; 

ReactDOM.render(<CreatePageTemplateLog
    socketIo={socket}
    listItems={receivedFromServer} />, document.getElementById("main-page-content"));