import React from "react";
import ReactDOM from "react-dom";
import { Badge, Button, Col, Row, Form, InputGroup } from "react-bootstrap";
import { makeStyles } from "@material-ui/core/styles";
import { blue, red } from "@material-ui/core/colors";
import Card from "@material-ui/core/Card";
import CardActions from "@material-ui/core/CardActions";
import CardContent from "@material-ui/core/CardContent";
import Typography from "@material-ui/core/Typography";
import Radio from "@material-ui/core/Radio";
import ButtonUI from "@material-ui/core/Button";
import Checkbox from "@material-ui/core/Checkbox";
import FormGroup from "@material-ui/core/FormGroup";
import RadioGroup from "@material-ui/core/RadioGroup";
import FormControl from "@material-ui/core/FormControl";
import FormControlLabel from "@material-ui/core/FormControlLabel";
import { TimePicker, MuiPickersUtilsProvider } from "material-ui-pickers";
import DateFnsUtils from "dateIoFnsUtils";
import PropTypes from "prop-types";

import CreateChipSource from "../commons/createChipSource.jsx";
import CreateSourceList from "../commons/createSourceList.jsx";
import CreateDateTimePicker from "../commons/createDateTimePicker.jsx";
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

function CreateChangeTemplateType(props){
    return (
        <RadioGroup 
            aria-label="gender" 
            name="templateType" 
            value={props.templateType} 
            onChange={props.handlerChangeTemplateType}>
            <FormControlLabel className="mb-n2" value="telemetry" control={<Radio color="primary" size="small" />} label="телеметрия" />
            <FormControlLabel value="filtration" control={<Radio color="primary" size="small" />} label="фильтрация" />
        </RadioGroup>
    );
}

CreateChangeTemplateType.propTypes = {
    templateType: PropTypes.string.isRequired,
    handlerChangeTemplateType: PropTypes.func.isRequired,
};

function CreateFormControlChangeTime(props){
    let createListDays = () => {
        let listChecbox = [];

        for(let dayOfWeek in props.listSelectedDays){
            let checkboxColor = (dayOfWeek === "Sat" || dayOfWeek === "Sun") ? "secondary": "primary";

            listChecbox.push(<FormControlLabel
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
                <RadioGroup 
                    aria-label="gender" 
                    name="templateTime" 
                    value={props.checkSelectedType} 
                    onChange={props.handlerChangeTemplateTimeRadioType}>
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
                    selectedDate={props.timeTrigger} 
                    handleDateChange={props.handlerChangeTimeTrigger} />
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

function CreateProtocolList(props){
    const np = [
        {t:"any", n:"любой"},
        {t:"tcp", n:"tcp"},
        {t:"udp", n:"udp"},
    ];

    return (
        <select 
            defaultValue={props.defaultNetworkProtocol}
            className="custom-select custom-select-sm" 
            onChange={props.handlerChosen} 
            id="protocol_list">
            {np.map((item) => {
                return <option key={`key_p_${item.t}`} value={item.t}>{item.n}</option>;
            })}
        </select>
    );
}

CreateProtocolList.propTypes = {
    handlerChosen: PropTypes.func.isRequired,
    defaultNetworkProtocol: PropTypes.string.isRequired,
};

function ListInputValue(props){
    let isEmpty = true;

    done: 
    for(let et in props.inputValue){
        for(let d in props.inputValue[et]){
            if(props.inputValue[et][d].length > 0){
                isEmpty = false;

                break done;
            }
        }
    }

    if(isEmpty){
        return <React.Fragment></React.Fragment>;
    }

    let getList = (type) => {
        let getListDirection = (d) => {
            if(props.inputValue[type][d].length === 0){
                return { value: "", success: false };
            }

            let result = props.inputValue[type][d].map((item) => {
                if(d === "src"){
                    return <div className="ml-4" key={`elem_${type}_${d}_${item}`}>
                        <small className="text-info">{d}&#8592; </small>{item}
                            &nbsp;<a onClick={props.hendlerDeleteAddedElem.bind(this, {
                            type: type,
                            direction: d,
                            value: item
                        })} className="clickable_icon" href="#"><img src="../images/icons8-delete-16.png"></img></a>
                    </div>; 
                }
                if(d === "dst"){
                    return <div className="ml-4" key={`elem_${type}_${d}_${item}`}>
                        <small className="text-info">{d}&#8594; </small>{item}
                            &nbsp;<a onClick={props.hendlerDeleteAddedElem.bind(this, {
                            type: type,
                            direction: d,
                            value: item
                        })} className="clickable_icon" href="#"><img src="../images/icons8-delete-16.png"></img></a>
                    </div>; 
                }

                return <div className="ml-4" key={`elem_${type}_${d}_${item}`}>
                    <small className="text-info">{d}&#8596; </small>{item}
                        &nbsp;<a onClick={props.hendlerDeleteAddedElem.bind(this, {
                        type: type,
                        direction: d,
                        value: item
                    })} className="clickable_icon" href="#"><img src="../images/icons8-delete-16.png"></img></a>
                </div>; 
            });

            return { value: result, success: true };
        };

        let resultAny = getListDirection("any");
        let resultSrc = getListDirection("src");
        let resultDst = getListDirection("dst");

        return (
            <React.Fragment>
                <div>{resultAny.value}</div>
                {(resultAny.success && (resultSrc.success || resultDst.success)) ? <div className="text-danger text-center">&laquo;ИЛИ&raquo;</div> : <div></div>}                   
                <div>{resultSrc.value}</div>
                {(resultSrc.success && resultDst.success) ? <div className="text-danger text-center">&laquo;И&raquo;</div> : <div></div>}                   
                <div>{resultDst.value}</div>
            </React.Fragment>
        );
    };

    return (
        <React.Fragment>
            <Row>
                <Col sm="3" className="text-center">
                    <Badge variant="dark">ip адрес</Badge>
                </Col>
                <Col sm="1" className="text-danger text-center">&laquo;ИЛИ&raquo;</Col>
                <Col sm="3" className="text-center">
                    <Badge variant="dark">сеть</Badge>
                </Col>
                <Col sm="1" className="text-danger text-center">&laquo;И&raquo;</Col>
                <Col sm="4" className="text-center">
                    <Badge  variant="dark">сетевой порт</Badge>
                </Col>
            </Row>
            <Row>
                <Col sm="4">{getList("ip")}</Col>
                <Col sm="4">{getList("nw")}</Col>
                <Col sm="4">{getList("pt")}</Col>
            </Row>
        </React.Fragment>
    );
}

ListInputValue.propTypes = {
    inputValue: PropTypes.string.isRequired,
    hendlerDeleteAddedElem: PropTypes.func.isRequired,
};

function CreateForm(props){ 
    let daysOfWeek = [];
    let textColor = "text-primary";
    
    switch(props.numberSteppers){
    case 0:
        return (
            <Row>
                <Col md={12} className="text-center">
                    <CreateChangeTemplateType 
                        templateType={props.templateParameters.templateType}
                        handlerChangeTemplateType={props.handlerChangeTemplateType} />
                </Col>
            </Row>
        );

    case 1:
        return <CreateFormControlChangeTime
            timeTrigger={props.templateParameters.templateTime.timeTrigger}
            listSelectedDays={props.templateParameters.templateTime.listSelectedDays}
            checkSelectedType={props.templateParameters.templateTime.checkSelectedType}
            handlerChangeTimeTrigger={props.handlerChangeTimeTrigger}
            handlerChangeCheckboxDayOfWeek={props.handlerChangeCheckboxDayOfWeek}
            handlerChangeTemplateTimeRadioType={props.handlerChangeTemplateTimeRadioType} />;

    case 2:
        return (
            <React.Fragment>
                <Row className="pt-3">
                    <Col md={5} className="text-left">
                        <CreateSourceList 
                            typeModal={"новая"}
                            hiddenFields={false}
                            listSources={props.listSources}
                            currentSource={props.templateParameters.templeteChosedSource}
                            handlerChosen={props.handlerChosenSource}
                            swithCheckConnectionStatus={false} />        
                    </Col>
                    <Col md={7} className="mt-n1 text-left">
                        <CreateChipSource 
                            chipData={props.templateParameters.templateListSource} 
                            handleDelete={props.handlerDeleteSource}/>
                    </Col>
                </Row>
                <Row>
                    <Col md={12} className="text-left mt-n2">
                        <Typography variant="body2" color="textSecondary">
                            {"* если в поле \"выберите источник\" не выбран ни один из источников, то тогда считается что шаблон распространяется на все источники"}
                        </Typography>
                    </Col>
                </Row>
            </React.Fragment>
        );                           

    case 3:
        return (
            <React.Fragment>
                <Row className="mt-2">
                    <Col sm="3" className="text-right">
                        <small className="mr-1 text-muted">сетевой протокол</small>
                        <CreateProtocolList 
                            defaultNetworkProtocol={props.parametersFiltration.networkProtocol} 
                            handlerChosen={props.handlerChosenNetworkProtocol} />
                    </Col>
                    <Col sm="1"></Col>
                    <Col sm="8" className="mt-2">
                        <CreateDateTimePicker 
                            currentDateTimeStart={props.parametersFiltration.dateTime.currentDateTimeStart}
                            currentDateTimeEnd={props.parametersFiltration.dateTime.currentDateTimeEnd}
                            handlerChangeDateTimeStart={props.handlerChangeDateTimeStart}
                            handlerChangeDateTimeEnd={props.handlerChangeDateTimeEnd} />
                    </Col>
                </Row>
                <Row className="mt-3">
                    <Col className="text-center" sm="4">
                        <Form inline>
                            <Form.Check onClick={props.handlerCheckRadioInput} custom type="radio" id="r_direction_any" value="any" label="any" className="mt-1 ml-3" name="choseNwType" defaultChecked />
                            <Form.Check onClick={props.handlerCheckRadioInput} custom type="radio" id="r_direction_src" value="src" label="src" className="mt-1 ml-3" name="choseNwType" />
                            <Form.Check onClick={props.handlerCheckRadioInput} custom type="radio" id="r_direction_dst" value="dst" label="dst" className="mt-1 ml-3" name="choseNwType" />
                        </Form>
                    </Col>
                    <Col sm="8"> 
                        <InputGroup className="mb-3" size="sm">
                            <FormControl
                                id="input_ip_network_port"
                                aria-describedby="basic-addon2"
                                onChange={props.handlerInput}
                                onKeyPress={props.handleKeyPress}
                                isValid={props.parametersFiltration.inputFieldIsValid}
                                isInvalid={props.parametersFiltration.inputFieldIsInvalid} 
                                placeholder="введите ip адрес, подсеть или сетевой порт" />
                            <InputGroup.Append>
                                <Button onClick={props.handlerAddPortNetworkIP} variant="outline-secondary">
                                    добавить
                                </Button>
                            </InputGroup.Append>
                        </InputGroup>
                    </Col>
                </Row>
                <ListInputValue 
                    inputValue={props.parametersFiltration.inputValue}
                    hendlerDeleteAddedElem={props.hendlerDeleteAddedElem} />
            </React.Fragment>
        );

    case 4: 
        for(let day in props.templateParameters.templateTime.listSelectedDays){
            if(props.templateParameters.templateTime.listSelectedDays[day].checked){
                daysOfWeek.push(props.templateParameters.templateTime.listSelectedDays[day].name);
            }
        }

        return (
            <React.Fragment>
                <Row>
                    <Col md={12} className="text-left">
                        <Typography variant="subtitle1" color="textSecondary">
                        Подготовлен шаблон со следующими параметрами:
                        </Typography>
                    </Col>
                </Row>
                <Row>
                    <Col md={4} className="text-right">
                        <Typography variant="subtitle1" color="textSecondary">тип шаблона:</Typography>
                    </Col>
                    <Col md={8} className="text-left">{(props.templateParameters.templateType === "telemetry") ? "телеметрия": "фильтрация"}</Col>
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
                            let hour = props.templateParameters.templateTime.timeTrigger.getHours();
                            let minute = props.templateParameters.templateTime.timeTrigger.getMinutes();

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
                            if(props.templateParameters.templateListSource.length === 0){
                                return "на всех источниках";
                            }

                            return props.templateParameters.templateListSource.map((item) => {
                                return <Badge pill variant="secondary" className="mr-1" key={`key_sid_${item}`}>{item}</Badge>;
                            });
                        })()}
                    </Col>
                </Row>
            </React.Fragment>
        );

    default:
        return <Row><Col md={12}>Ошибка!!!</Col></Row>;
    }
}

CreateForm.propTypes = {
    listSources: PropTypes.object.isRequired,
    numberSteppers: PropTypes.number.isRequired,
    templateParameters: PropTypes.object.isRequired,
    parametersFiltration: PropTypes.object.isRequired,
    handlerInput: PropTypes.func.isRequired,
    handleKeyPress: PropTypes.func.isRequired,
    handlerAddPortNetworkIP: PropTypes.func.isRequired,
    handlerChangeDateTimeStart: PropTypes.func.isRequired,
    handlerChangeDateTimeEnd: PropTypes.func.isRequired,
    handlerCheckRadioInput: PropTypes.func.isRequired,
    hendlerDeleteAddedElem: PropTypes.func.isRequired,
    handlerChosenSource: PropTypes.func.isRequired,
    handlerDeleteSource: PropTypes.func.isRequired,
    handlerChangeTimeTrigger: PropTypes.func.isRequired,
    handlerChangeTemplateType: PropTypes.func.isRequired,
    handlerChosenNetworkProtocol: PropTypes.func.isRequired,
    handlerChangeCheckboxDayOfWeek: PropTypes.func.isRequired,
    handlerChangeTemplateTimeRadioType: PropTypes.func.isRequired,
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
    handlerChangeTimeTrigger: PropTypes.func.isRequired,
    handlerChangeTemplateType: PropTypes.func.isRequired,
    handlerChosenNetworkProtocol: PropTypes.func.isRequired,
    handlerChangeCheckboxDayOfWeek: PropTypes.func.isRequired,
    handlerChangeTemplateTimeRadioType: PropTypes.func.isRequired,
};

function CreateCardTaskTemplates(props){
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

    return (
        <Card>
            <CardContent>
                <Row>
                    <Col md={12} className="text-left">
                        <Typography variant="subtitle1" color="textSecondary">
                        Шаблон добавлен {formatter.format(props.templatesInformation.timeCreation)}, пользователем {props.templatesInformation.userName}.
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
                {(Object.keys(props.templatesInformation.taskParameters).length > 0) ? <Row>
                    <Col>{JSON.stringify(props.templatesInformation.taskParameters)}</Col>
                </Row> : ""}
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
                networkProtocol: "tcp",
                inputRadioType: "any",
                dateTime: {
                    currentDateTimeStart: new Date,
                    currentDateTimeEnd: new Date,
                },
                inputFieldIsValid: false,
                inputFieldIsInvalid: false,
                inputValue: "",
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
        if(this.state.templateParameters.templateType === "telemetry"){
            let listSelectedDays = (() => {
                let selectedDays = {};
                for(let day in this.state.templateParameters.templateTime.listSelectedDays){
                    if(this.state.templateParameters.templateTime.listSelectedDays[day].checked){
                        selectedDays[day] = this.state.templateParameters.templateTime.listSelectedDays[day].name;
                    }
                }

                return selectedDays;
            })();
            
            if(Object.keys(listSelectedDays).length === 0){
                return;
            }

            this.props.socketIo.emit("network interaction: create new template", { 
                arguments: {
                    type: this.state.templateParameters.templateType,
                    timeSettings: {
                        timeTrigger: {
                            hour: this.state.templateParameters.templateTime.timeTrigger.getHours(),
                            minutes:this.state.templateParameters.templateTime.timeTrigger.getMinutes(),
                        },
                        listSelectedDays: listSelectedDays,
                    },
                    listSources: this.state.templateParameters.templateListSource,
                } 
            });

            this.handlerButtonCancel();

            return;
        }

        console.log("тип шаблона - фильтрация");
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

    handlerChosenNetworkProtocol(proto){
        console.log("func 'handlerChosenNetworkProtocol', START...");
        console.log(proto);
    }

    handlerChangeDateTimeStart(dateTime){
        console.log("func 'handlerChangeDateTimeStart', START...");
        console.log(dateTime);
    }
    
    handlerChangeDateTimeEnd(dateTime){
        console.log("func 'handlerChangeDateTimeEnd', START...");
        console.log(dateTime);
    }

    handlerCheckRadioInput(data){
        console.log("func 'handlerCheckRadioInput', START...");
        console.log(data);
    }

    handlerInput(element){
        console.log("func 'handlerInput', START...");
        console.log(element);
    }

    handleKeyPress(){
        console.log("func 'handleKeyPress', START...");
    }

    handlerAddPortNetworkIP(){
        console.log("func 'handlerAddPortNetworkIP', START...");
    }

    hendlerDeleteAddedElem(data){
        console.log("func 'hendlerDeleteAddedElem', START...");
        console.log(data);
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