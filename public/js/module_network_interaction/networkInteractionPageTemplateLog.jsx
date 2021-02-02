import React from "react";
import ReactDOM from "react-dom";
import { Button, Col, Row } from "react-bootstrap";
import { makeStyles } from "@material-ui/core/styles";
import { blue, red } from "@material-ui/core/colors";
import Card from "@material-ui/core/Card";
import CardActions from "@material-ui/core/CardActions";
import CardContent from "@material-ui/core/CardContent";
import ButtonUI from "@material-ui/core/Button";
import PropTypes from "prop-types";

import { helpers } from "../common_helpers/helpers.js";
import CreateForm from "./pageTemplateLogElements/createForm.jsx";
import CreateCardTaskTemplates from "./pageTemplateLogElements/createCardTaskTemplates.jsx";
import CreateSteppersTemplateLog from "../commons/createSteppersTemplateLog.jsx";
import { ModalWindowConfirmMessage } from "../commons/modalWindowConfirmMessage.jsx";

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
    colorPrimary: {
        color: blue[500],
    },
    colorWarning: {
        color: red[500],
    },
    cardHeight: {
        minHeight: 220,
    },
}));

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
                    className={classes.colorPrimary}
                    size="small"
                    color="primary" 
                    onClick={props.handlerButtonFinish}>
                    завершить
                </ButtonUI>
            );
        } else {
            return (
                <ButtonUI 
                    className={classes.colorPrimary}
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
                    className={classes.colorWarning}
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

function CreateCard(props){
    const classes = useStyles();

    return (
        <Card>
            <CardContent className={classes.cardHeight}>
                <CreateForm
                    listSources={props.listSources} 
                    numberSteppers={props.numberSteppers}
                    templateParameters={props.templateParameters}
                    parametersFiltration={props.parametersFiltration}
                    handlerInput={props.handlerInput}
                    handleKeyPress={props.handleKeyPress}
                    handlerAddPortNetworkIP={props.handlerAddPortNetworkIP}
                    handlerChangeDateTimeStart={props.handlerChangeDateTimeStart}
                    handlerChangeDateTimeEnd={props.handlerChangeDateTimeEnd}
                    handlerCheckRadioInput={props.handlerCheckRadioInput}
                    hendlerDeleteAddedElem={props.hendlerDeleteAddedElem}
                    handlerChosenSource={props.handlerChosenSource}
                    handlerDeleteSource={props.handlerDeleteSource}
                    handlerChangeRangeSlider={props.handlerChangeRangeSlider}
                    handlerChangeTemplateType={props.handlerChangeTemplateType}
                    handlerChangeTimeTrigger={props.handlerChangeTimeTrigger}
                    handlerChosenNetworkProtocol={props.handlerChosenNetworkProtocol}
                    handlerChangeCheckboxDayOfWeek={props.handlerChangeCheckboxDayOfWeek}
                    handlerChangeTemplateTimeRadioType={props.handlerChangeTemplateTimeRadioType} />
            </CardContent>
            <CardActions>
                <CreateButtons 
                    numberSteppers={props.numberSteppers}
                    templateParameters={props.templateParameters}
                    handlerButtonBack={props.handlerButtonBack}
                    handlerButtonNext={props.handlerButtonNext}
                    handlerButtonCancel={props.handlerButtonCancel}
                    handlerButtonFinish={props.handlerButtonFinish} />
            </CardActions>                
        </Card>
    );
}

CreateCard.propTypes = {
    listSources: PropTypes.object.isRequired,
    numberSteppers: PropTypes.number.isRequired,
    handlerButtonBack: PropTypes.func.isRequired,
    handlerButtonNext: PropTypes.func.isRequired,
    templateParameters: PropTypes.object.isRequired,
    parametersFiltration: PropTypes.object.isRequired,
    handlerInput: PropTypes.func.isRequired,
    handleKeyPress: PropTypes.func.isRequired,
    handlerAddPortNetworkIP: PropTypes.func.isRequired,
    handlerChangeDateTimeStart: PropTypes.func.isRequired,
    handlerChangeDateTimeEnd: PropTypes.func.isRequired,
    handlerCheckRadioInput: PropTypes.func.isRequired,
    hendlerDeleteAddedElem: PropTypes.func.isRequired,
    handlerButtonCancel: PropTypes.func.isRequired,
    handlerButtonFinish: PropTypes.func.isRequired,
    handlerChosenSource:PropTypes.func.isRequired,
    handlerDeleteSource:PropTypes.func.isRequired,
    handlerChangeRangeSlider: PropTypes.func.isRequired,
    handlerChangeTimeTrigger: PropTypes.func.isRequired,
    handlerChangeTemplateType: PropTypes.func.isRequired,
    handlerChosenNetworkProtocol: PropTypes.func.isRequired,
    handlerChangeCheckboxDayOfWeek: PropTypes.func.isRequired,
    handlerChangeTemplateTimeRadioType: PropTypes.func.isRequired,
};

class CreatePageTemplateLog extends React.Component {
    constructor(props){
        super(props);

        this.state = {
            showForm: false,
            showButtonAddTask: true,
            showModalWindowDeleteTemplate: false,
            idDeletedTemplate: "",
            steppers: ["тип задачи" , "время", "источники", "параметры фильтрации", "завершить"],
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
                templateListSource: [],
                templeteChosedSource: 0,
            },
            listTaskTemplates: {},
            parametersFiltration: {
                networkProtocol: "any",
                inputRadioType: "any",
                dateTime: {
                    currentDateTimeStart: new Date,
                    currentDateTimeEnd: new Date,
                    minHour: 3,
                    maxHour: 4,
                },
                inputs: {
                    inputFieldIsValid: false,
                    inputFieldIsInvalid: false,
                    inputValue: {
                        ip: { any: [], src: [], dst: [] },
                        pt: { any: [], src: [], dst: [] },
                        nw: { any: [], src: [], dst: [] },
                    },
                    currentInputValue: "",
                    typeCurrentInputValue: "none"
                },
            },
        };

        this.handlerButtonCancel = this.handlerButtonCancel.bind(this);
        this.handlerButtonAddTask = this.handlerButtonAddTask.bind(this);

        this.handlerEvents.call(this);
        this.requestEmitter.call(this);
    }

    handlerEvents(){
        this.props.socketIo.on("network interaction: response list new template", (data) => {
            this.setState({ listTaskTemplates: data.arguments });
        });

        this.props.socketIo.on("network interaction: response del new temp task", (data) => {
            let listTaskTemplates = Object.assign({}, this.state.listTaskTemplates);
            delete listTaskTemplates[data.arguments.templateID];
            this.setState({ listTaskTemplates: listTaskTemplates });
        });
    }

    requestEmitter(){
        this.props.socketIo.emit("network interaction: get all list template", {});
    }

    handlerButtonAddTask(){
        this.setState({ 
            showForm: true,
            showButtonAddTask: false,
        });
    }

    handlerButtonBack(){
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
        let listSelectedDays = (() => {
            let selectedDays = {};
            for(let day in this.state.templateParameters.templateTime.listSelectedDays){
                if(this.state.templateParameters.templateTime.listSelectedDays[day].checked){
                    selectedDays[day] = this.state.templateParameters.templateTime.listSelectedDays[day].name;
                }
            }

            return selectedDays;
        })();
               
        let objData = {
            type: this.state.templateParameters.templateType,
            timeSettings: {
                timeTrigger: {
                    hour: this.state.templateParameters.templateTime.timeTrigger.getHours(),
                    minutes:this.state.templateParameters.templateTime.timeTrigger.getMinutes(),
                },
                listSelectedDays: listSelectedDays,
            },
            listSources: this.state.templateParameters.templateListSource,
            parametersFiltration: {},
        };
        
        if(this.state.templateParameters.templateType === "filtration"){
            objData.parametersFiltration = {
                networkProtocol: this.state.parametersFiltration.networkProtocol,
                startDate: +new Date(this.state.parametersFiltration.dateTime.currentDateTimeStart),
                endDate: +new Date(this.state.parametersFiltration.dateTime.currentDateTimeEnd),
                inputValue: this.state.parametersFiltration.inputs.inputValue,
            };
        }

        //проверяем на наличие незаполненных полей в ключевых шагах 
        if(this.state.stepsError.length > 0){
            return;
        }

        this.props.socketIo.emit("network interaction: create new template", { arguments: objData });

        this.handlerButtonCancel();
    }

    handlerButtonCancel(){
        this.setState({
            showForm: false,
            showButtonAddTask: true,
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
                templateListSource: [],
                templeteChosedSource: 0,
            },
            listTaskTemplates: {},
            parametersFiltration: {
                networkProtocol: "any",
                inputRadioType: "any",
                dateTime: {
                    currentDateTimeStart: new Date,
                    currentDateTimeEnd: new Date,
                    minHour: 3,
                    maxHour: 4,
                },
                inputs: {
                    inputFieldIsValid: false,
                    inputFieldIsInvalid: false,
                    inputValue: {
                        ip: { any: [], src: [], dst: [] },
                        pt: { any: [], src: [], dst: [] },
                        nw: { any: [], src: [], dst: [] },
                    },
                    currentInputValue: "",
                    typeCurrentInputValue: "none"
                },
            },
        });
    }

    handlerCheckForm(){
        //проверяем форму с временем и днями недели
        if(this.state.numberSteppers === 1){
            let stepsError = this.state.stepsError;

            let dayIsChange = false;
            //выбран ли хотя бы один день недели
            for(let dayOfWeek in this.state.templateParameters.templateTime.listSelectedDays){
                if(this.state.templateParameters.templateTime.listSelectedDays[dayOfWeek].checked){
                    dayIsChange = true;
                }
            } 

            if(!dayIsChange){
                stepsError.push(1);
            } else {
                let foundIndex = this.state.stepsError.indexOf(1);
                if(foundIndex !== -1){
                    stepsError.splice(foundIndex - 1, 1);       
                }
            }

            this.setState({ stepsError: stepsError });
        }

        //проверяем форму с параметрами фильтрации
        if(this.state.numberSteppers === 3 && this.state.templateParameters.templateType === "filtration"){
            let checkExistInputValue = () => {
                let isEmpty = true;
    
                done:
                for(let et in this.state.parametersFiltration.inputs.inputValue){
                    for(let d in this.state.parametersFiltration.inputs.inputValue[et]){
                        if(Array.isArray(this.state.parametersFiltration.inputs.inputValue[et][d]) && this.state.parametersFiltration.inputs.inputValue[et][d].length > 0){
                            isEmpty = false;
    
                            break done;  
                        }
                    }
                }
    
                return isEmpty;
            };

            let stepsError = this.state.stepsError;

            //проверяем наличие хотя бы одного параметра в inputValue
            if(checkExistInputValue()){
                stepsError.push(3);
            } else {
                let foundIndex = this.state.stepsError.indexOf(3);
                if(foundIndex !== -1){
                    stepsError.splice(foundIndex - 1, 1);       
                }
            }

            this.setState({ stepsError: stepsError });
        }
    }

    handlerChangeTemplateType(event){
        let templateParameters = this.state.templateParameters;
        templateParameters.templateType = event.target.value;

        this.setState({ templateParameters: templateParameters });
    }

    handlerChangeTemplateTimeRadioType(event){
        const value = event.target.value;
        let templateParameters = Object.assign({}, this.state.templateParameters);
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

    handlerChangeCheckboxDayOfWeek(event){       
        const value = event.target.value;
        let templateParameters = Object.assign({}, this.state.templateParameters);

        for(let dayOfWeek in templateParameters.templateTime.listSelectedDays){
            if(dayOfWeek === value){
                templateParameters.templateTime.listSelectedDays[dayOfWeek].checked = !templateParameters.templateTime.listSelectedDays[dayOfWeek].checked;
    
                break;
            }
        }

        this.setState({ templateParameters: templateParameters });
    }

    handlerChangeTimeTrigger(date){
        let templateParameters = Object.assign({}, this.state.templateParameters);
        templateParameters.templateTime.timeTrigger = date;
        this.setState({ templateParameters: templateParameters });
    }

    handlerChosenSource(event){
        let sourceID = +event.target.value;
        
        if((sourceID === null) || (typeof sourceID === "undefined") || (sourceID === 0)){
            return;
        }

        if(this.state.templateParameters.templateListSource.includes(sourceID)){
            return;
        }

        let templateParameters = Object.assign({}, this.state.templateParameters);
        templateParameters.templeteChosedSource = sourceID;
        templateParameters.templateListSource.push(sourceID);
        templateParameters.templateListSource.sort(this.compareNumeric);
        this.setState({ templateParameters: templateParameters });
    }

    handlerDeleteSource(sourceID){
        if(!this.state.templateParameters.templateListSource.includes(sourceID)){
            return null;
        }

        let templateParameters = Object.assign({}, this.state.templateParameters);
        templateParameters.templateListSource.splice((templateParameters.templateListSource.indexOf(sourceID)), 1);
        this.setState({ templateParameters: templateParameters });
    }

    handlerDeleteCardTemplateInformation(){
        this.props.socketIo.emit("network interaction: delete template", { arguments: { templateID: this.state.idDeletedTemplate } });

        //после передачи через socketIo очищаем значение idDeletedTemplate
        this.setState({ 
            idDeletedTemplate: "",
            showModalWindowDeleteTemplate: false,
        });
    }

    handlerCloseModalWindowDeleteTemplate(){
        this.setState({ showModalWindowDeleteTemplate: false });
    }

    handlerShowModalWindowDeleteTemplate(id){
        this.setState({ 
            idDeletedTemplate: id,
            showModalWindowDeleteTemplate: true 
        });
    }

    handlerChosenNetworkProtocol(e){
        let objTmp = Object.assign({}, this.state.parametersFiltration);
        objTmp.networkProtocol = e.target.value;
        this.setState({ parametersFiltration: objTmp });
    }

    handlerChangeDateTimeStart(date){
        let objTmp = Object.assign({}, this.state.parametersFiltration);
        objTmp.dateTime.currentDateTimeStart = date;
        this.setState({ parametersFiltration: objTmp });
    }
    
    handlerChangeDateTimeEnd(date){
        let objTmp = Object.assign({}, this.state.parametersFiltration);
        objTmp.dateTime.currentDateTimeEnd = date;
        this.setState({ parametersFiltration: objTmp });
    }

    handlerCheckRadioInput(e){
        let objTmp = Object.assign({}, this.state.parametersFiltration);
        objTmp.inputRadioType = e.target.value;
        this.setState({ parametersFiltration: objTmp });
    }

    handlerInput(e){
        let value = e.target.value.replace(/,/g, ".");      
        let objTmp = Object.assign({}, this.state.parametersFiltration);
        if(value.includes(".")){
            if(value.includes("/")){
                if(helpers.checkInputValidation({
                    "name": "network", 
                    "value": value, 
                })){
                    objTmp.inputs.inputFieldIsValid = true;
                    objTmp.inputs.inputFieldIsInvalid = false;
                    objTmp.inputs.currentInputValue = value;
                    objTmp.inputs.typeCurrentInputValue = "nw";
                } else {  
                    objTmp.inputs.inputFieldIsValid = false;
                    objTmp.inputs.inputFieldIsInvalid = true;
                    objTmp.inputs.currentInputValue = "";
                    objTmp.inputs.typeCurrentInputValue = "none";
                }
            } else {
                if(helpers.checkInputValidation({
                    "name": "ipaddress", 
                    "value": value, 
                })){                  
                    objTmp.inputs.inputFieldIsValid = true;
                    objTmp.inputs.inputFieldIsInvalid = false;
                    objTmp.inputs.currentInputValue = value;
                    objTmp.inputs.typeCurrentInputValue = "ip";
                } else {  
                    objTmp.inputs.inputFieldIsValid = false;
                    objTmp.inputs.inputFieldIsInvalid = true;
                    objTmp.inputs.currentInputValue = "";
                    objTmp.inputs.typeCurrentInputValue = "none";
                }
            }
        } else {
            if(helpers.checkInputValidation({
                "name": "port", 
                "value": value, 
            })){
                objTmp.inputs.inputFieldIsValid = true;
                objTmp.inputs.inputFieldIsInvalid = false;
                objTmp.inputs.currentInputValue = value;
                objTmp.inputs.typeCurrentInputValue = "pt";
            } else {
                objTmp.inputs.inputFieldIsValid = false;
                objTmp.inputs.inputFieldIsInvalid = true;
                objTmp.inputs.currentInputValue = "";
                objTmp.inputs.typeCurrentInputValue=  "none";
            }
        }

        this.setState({ parametersFiltration: objTmp });
    }

    handlerAddPortNetworkIP(){
        if(this.state.parametersFiltration.inputs.typeValueInput === "none"){
            return;
        }

        let typeInput = this.state.parametersFiltration.inputs.typeCurrentInputValue;
        let typeRadio = this.state.parametersFiltration.inputRadioType;

        let objUpdate = Object.assign({}, this.state.parametersFiltration);
        if(Array.isArray(objUpdate.inputs.inputValue[typeInput][typeRadio])){
            if(objUpdate.inputs.inputValue[typeInput][typeRadio].includes(this.state.parametersFiltration.inputs.currentInputValue)){
                return;
            }

            objUpdate.inputs.inputValue[typeInput][typeRadio].push(this.state.parametersFiltration.inputs.currentInputValue);

            this.setState({ parametersFiltration: objUpdate });
        }

        document.getElementById("input_ip_network_port").value = "";
    }

    hendlerDeleteAddedElem(data){
        let objUpdate = Object.assign({}, this.state.parametersFiltration);
        if(Array.isArray(objUpdate.inputs.inputValue[data.type][data.direction])){
            let list = objUpdate.inputs.inputValue[data.type][data.direction];
            objUpdate.inputs.inputValue[data.type][data.direction] = list.filter((item) => (item !== data.value));

            this.setState({ parametersFiltration: objUpdate });
        }
    }

    handleKeyPress(event){
        if(event.key == "Enter"){
            this.handlerAddPortNetworkIP();
        }
    }

    handlerChangeRangeSlider(e, [ min, max ]){
        let objUpdate = Object.assign({}, this.state.parametersFiltration);
        objUpdate.dateTime.minHour = min;
        objUpdate.dateTime.maxHour = max;
        this.setState({ parametersFiltration: objUpdate });
    }

    createTemplateList(){
        if(this.state.showForm){
            return null;
        }

        if(Object.keys(this.state.listTaskTemplates).length === 0){
            return null;
        }

        let listTemplate = [];
        for(let templateID in this.state.listTaskTemplates){
            listTemplate.push({
                id: templateID,
                timeCreation: this.state.listTaskTemplates[templateID].timeCreation,
            });    
        }        

        listTemplate.sort((a, b) => {
            if(a.timeCreation > b.timeCreation) return 1;
            if(a.timeCreation === b.timeCreation) return 0;
            if(a.timeCreation < b.timeCreation) return -1;
        });
        listTemplate.reverse();

        return (
            <React.Fragment>
                {listTemplate.map((item) => {
                    return (
                        <Row key={`key_template_id_${item.id}`} className="mb-2">
                            <Col md={12}>
                                <CreateCardTaskTemplates
                                    templatesInformation={this.state.listTaskTemplates[item.id]}
                                    handlerDeteteCard={this.handlerShowModalWindowDeleteTemplate.bind(this, item.id)} />
                            </Col>
                        </Row>
                    );
                })}
            </React.Fragment>
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
                            <CreateCard 
                                listSources={this.props.listItems.listSources}
                                numberSteppers={this.state.numberSteppers}
                                handlerButtonBack={this.handlerButtonBack.bind(this)}
                                handlerButtonNext={this.handlerButtonNext.bind(this)}
                                templateParameters={this.state.templateParameters}
                                parametersFiltration={this.state.parametersFiltration}
                                handlerInput={this.handlerInput.bind(this)}
                                handleKeyPress={this.handleKeyPress.bind(this)}
                                handlerAddPortNetworkIP={this.handlerAddPortNetworkIP.bind(this)}
                                handlerChangeDateTimeStart={this.handlerChangeDateTimeStart.bind(this)}
                                handlerChangeDateTimeEnd={this.handlerChangeDateTimeEnd.bind(this)}
                                handlerCheckRadioInput={this.handlerCheckRadioInput.bind(this)}
                                hendlerDeleteAddedElem={this.hendlerDeleteAddedElem.bind(this)}
                                handlerButtonCancel={this.handlerButtonCancel}
                                handlerButtonFinish={this.handlerButtonFinish.bind(this)}
                                handlerChosenSource={this.handlerChosenSource.bind(this)}
                                handlerDeleteSource={this.handlerDeleteSource.bind(this)}
                                handlerChangeRangeSlider={this.handlerChangeRangeSlider.bind(this)}
                                handlerChangeTimeTrigger={this.handlerChangeTimeTrigger.bind(this)}
                                handlerChangeTemplateType={this.handlerChangeTemplateType.bind(this)}
                                handlerChosenNetworkProtocol={this.handlerChosenNetworkProtocol.bind(this)}
                                handlerChangeCheckboxDayOfWeek={this.handlerChangeCheckboxDayOfWeek.bind(this)}
                                handlerChangeTemplateTimeRadioType={this.handlerChangeTemplateTimeRadioType.bind(this)} />
                        </Col>
                        <Col md={1}></Col>
                    </Row>}
                {this.createBottonAddTask.call(this)}
                {this.createTemplateList.call(this)}

                <ModalWindowConfirmMessage 
                    show={this.state.showModalWindowDeleteTemplate}
                    onHide={this.handlerCloseModalWindowDeleteTemplate.bind(this)}
                    msgBody={"Вы действительно хотите удалить выбранный шаблон?"}
                    msgTitle={"Удаление"}
                    nameDel={""}
                    handlerConfirm={this.handlerDeleteCardTemplateInformation.bind(this)} />
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