import React from "react";
import ReactDOM from "react-dom";
import { Button, Col, Row } from "react-bootstrap";
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
import FormLabel from "@material-ui/core/FormLabel";
import RadioGroup from "@material-ui/core/RadioGroup";
import FormControl from "@material-ui/core/FormControl";
import FormControlLabel from "@material-ui/core/FormControlLabel";
import { TimePicker, MuiPickersUtilsProvider } from "material-ui-pickers";
import DateFnsUtils from "dateIoFnsUtils";
import PropTypes from "prop-types";

import CreateChipSource from "../commons/createChipSource.jsx";
import CreateSourceList from "../commons/createSourceList.jsx";
import CreateSteppersTemplateLog from "../commons/createSteppersTemplateLog.jsx";

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
    }
}));

function CreateChangeTemplateType(props){
    return (
        <RadioGroup 
            aria-label="gender" 
            name="templateType" 
            value={props.templateType} 
            onChange={props.handlerChangeTemplateType}>
            <FormControlLabel className="mb-n2" value="telemetry" control={<Radio color="primary" size="small" />} label="телеметрия" />
            <FormControlLabel value="filtration" disabled control={<Radio color="primary" size="small" />} label="фильтрация" />
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

function CreateForm(props){ 
    let daysOfWeek = [];
    
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
            <FormControl component="fieldset">
                <FormLabel component="legend">Выбор параметров</FormLabel>
            </FormControl>
        );

    case 4:       
        /**
 * templateParameters: {
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
 */

        for(let day in props.templateParameters.templateTime.listSelectedDays){
            if(props.templateParameters.templateTime.listSelectedDays[day].checked){
                daysOfWeek.push(props.templateParameters.templateTime.listSelectedDays[day].name);
            }
        }

        /**
 * 
 * Дни недели можно подсветить синие - рабочие, красные - выходные
 */

        return (
            <React.Fragment>
                <Row>
                    <Col md={12} className="text-left">
                        <Typography variant="body2" color="textSecondary">
                        Подготовлен шаблон со следующими параметрами:
                        </Typography>
                    </Col>
                </Row>
                <Row>
                    <Col md={4} className="text-right">тип шаблона:</Col>
                    <Col md={8} className="text-left"><i>{(props.templateParameters.templateType === "telemetry") ? "телеметрия": "фильтрация"}</i></Col>
                </Row>
                <Row>
                    <Col md={4} className="text-right">дни недели:</Col>
                    <Col md={8} className="text-left"><i>{daysOfWeek.join()}</i></Col>
                </Row>
                <FormControl component="fieldset">
                    <FormLabel component="legend">Завершение создания шаблона</FormLabel>
                    {JSON.stringify(props.templateParameters)}
                </FormControl>
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
    handlerChosenSource: PropTypes.func.isRequired,
    handlerDeleteSource: PropTypes.func.isRequired,
    handlerChangeTimeTrigger: PropTypes.func.isRequired,
    handlerChangeTemplateType: PropTypes.func.isRequired,
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
                    handlerChosenSource={props.handlerChosenSource}
                    handlerDeleteSource={props.handlerDeleteSource}
                    handlerChangeTemplateType={props.handlerChangeTemplateType}
                    handlerChangeTimeTrigger={props.handlerChangeTimeTrigger}
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
    handlerButtonCancel: PropTypes.func.isRequired,
    handlerButtonFinish: PropTypes.func.isRequired,
    handlerChosenSource:PropTypes.func.isRequired,
    handlerDeleteSource:PropTypes.func.isRequired,
    handlerChangeTimeTrigger: PropTypes.func.isRequired,
    handlerChangeTemplateType: PropTypes.func.isRequired,
    handlerChangeCheckboxDayOfWeek: PropTypes.func.isRequired,
    handlerChangeTemplateTimeRadioType: PropTypes.func.isRequired,
};

class CreatePageTemplateLog extends React.Component {
    constructor(props){
        super(props);

        this.state = {
            showForm: false,
            showButtonAddTask: true,
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
        };

        this.handlerButtonAddTask = this.handlerButtonAddTask.bind(this);
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
        console.log("func 'handlerButtonFinish', START");
        console.log("выполняем обработку запроса на добавление шаблона");
    
        let numberSteppers = this.state.numberSteppers;
        if(this.state.templateParameters.templateType === "telemetry" && numberSteppers === 2){
            this.setState({ numberSteppers: 4 });

            return;
        }
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
                templateParameters.templateTime.listSelectedDays[dayOfWeek].checked = true;
    
                break;
            }
        }

        this.setState({ templateParameters: templateParameters });
    }

    handlerChangeTimeTrigger(date){
        console.log("func 'handlerChangeTimeTrigger'");
        console.log(date);

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
            return;
        }

        let templateParameters = Object.assign({}, this.state.templateParameters);
        templateParameters.templateListSource.splice((templateParameters.templateListSource.indexOf(sourceID)), 1);
        this.setState({ templateParameters: templateParameters });
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
                                handlerButtonCancel={this.handlerButtonCancel.bind(this)}
                                handlerButtonFinish={this.handlerButtonFinish.bind(this)}
                                handlerChosenSource={this.handlerChosenSource.bind(this)}
                                handlerDeleteSource={this.handlerDeleteSource.bind(this)}
                                handlerChangeTimeTrigger={this.handlerChangeTimeTrigger.bind(this)}
                                handlerChangeTemplateType={this.handlerChangeTemplateType.bind(this)}
                                handlerChangeCheckboxDayOfWeek={this.handlerChangeCheckboxDayOfWeek.bind(this)}
                                handlerChangeTemplateTimeRadioType={this.handlerChangeTemplateTimeRadioType.bind(this)} />
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