import React from "react";
import ReactDOM from "react-dom";
import { Button, Col, Row } from "react-bootstrap";
import ButtonUI from "@material-ui/core/Button";
import FormControl from "@material-ui/core/FormControl";
import FormLabel from "@material-ui/core/FormLabel";
import PropTypes from "prop-types";

import CreateSteppersTemplateLog from "../commons/createSteppersTemplateLog.jsx";

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

            },
        };

        this.handlerButtonBack = this.handlerButtonBack.bind(this);
        this.handlerButtonNext = this.handlerButtonNext.bind(this);   
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

    handlerCheckForm(){
        //тут делаем валидацию НЕКОТРЫХ форм
        //пока для теста выберем форму с временем

        if(this.state.numberSteppers === 1){
            let stepsError = this.state.stepsError;
            stepsError.push(1);

            this.setState({ stepsError: stepsError });
        }
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

    createForm(){
        if(!this.state.showForm){
            return;
        }
        
        switch(this.state.numberSteppers){
        case 0:
            return (
                <FormControl component="fieldset">
                    <FormLabel component="legend">Тип шаблона</FormLabel>
                </FormControl>
            );

        case 1:
            return (
                <FormControl component="fieldset">
                    <FormLabel component="legend">Выбор времени</FormLabel>
                </FormControl>
            );

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
        if(!this.state.showForm){
            return;
        }

        let createButtonBack = () => {
            return <ButtonUI 
                onClick={this.handlerButtonBack} 
                disabled={this.state.numberSteppers === 0}>
            назад
            </ButtonUI>;
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
                return <ButtonUI 
                    color="primary" 
                    onClick={this.handlerButtonFinish}>
                завершить
                </ButtonUI>;
            } else {
                return <ButtonUI 
                    color="primary" 
                    onClick={this.handlerButtonNext}>
                вперед
                </ButtonUI>;
            }
        };



        return (
            <Row>
                <Col md={12} className="text-left">
                    {createButtonBack()}
                    {createButtonNext()}
                    <ButtonUI>отменить</ButtonUI>
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
                <Row>
                    <Col md={12}>{this.createForm.call(this)}</Col>
                </Row>
                <Row>
                    <Col md={12}>{this.createButtons.call(this)}</Col>
                </Row>
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