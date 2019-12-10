/**
 * Модуль формирования модального окна добавления нового пользователя
 * 
 * Версия 0.1, дата релиза 03.12.2019
 */

"use strict";

import React from "react";
import { Button, Modal, Form } from "react-bootstrap";
import PropTypes from "prop-types";

import { helpers } from "../common_helpers/helpers";
import { ModalAlertDangerMessage } from "../commons/modalAlertMessage.jsx";

export { ModalWindowAddEditUser };

class ModalWindowAddEditUser extends React.Component {
    constructor(props){
        super(props);

        this.props.listWorkGroup.sort();

        this.alertClose = this.alertClose.bind(this);
        this.handlerSave = this.handlerSave.bind(this);
        this.handlerClose = this.handlerClose.bind(this);
        this.handlerUserInput = this.handlerUserInput.bind(this);

        this.state = {
            alertShow: false,
            formElements: {
                userName: {
                    value: "",
                    isValid: false,
                    isInvalid: false,
                },
                login:{
                    value: "",
                    isValid: false,
                    isInvalid: false,
                },
                firstPassword: {
                    value: "",
                    isValid: false,
                    isInvalid: false,
                },
                secondPassword: {
                    value: "",
                    isValid: false,
                    isInvalid: false,    
                },
                workGroup: {
                    value: this.props.listWorkGroup[0],
                }
            },
        };
    }

    getKey(str){
        let key = 0;
        for (let i = 0; i < str.length; i++) {
            key += str.charCodeAt(i);
        }
        return key.toString();
    }

    handlerUserInput(event){
        const value = event.target.value;
        const elementName = event.target.id;

        const elemType = {
            userName: "stringAlphaRu",
            login: "stringAlphaNumEng",
            firstPassword: "stringPasswd",
            secondPassword: "stringPasswd",
        };

        let objUpdate = Object.assign({}, this.state);
        if(objUpdate.formElements[elementName] === "undefined"){
            return;
        }

        objUpdate.formElements[elementName].value = value;
        if(elementName === "workGroup"){
            this.setState( objUpdate );
            
            return;
        }

        if(helpers.checkInputValidation({name: elemType[elementName], value: value})){
            objUpdate.formElements[elementName].isInvalid = false;
            objUpdate.formElements[elementName].isValid = true;
        } else {
            objUpdate.formElements[elementName].isInvalid = true;
            objUpdate.formElements[elementName].isValid = false;
        }

        this.setState( objUpdate );
    }

    alertClose(){
        this.setState({alertShow: false});
    }
   
    handlerClose(){
        this.props.onHide();
    }

    handlerSave(){
        let userInputs = this.state.formElements;
        let firstPasswdIsInvalide = userInputs.firstPassword.isInvalid;
        let passwdIsEqual = (userInputs.firstPassword.value.localeCompare(userInputs.secondPassword.value) === 0);

        console.log(`passwd is equal:${passwdIsEqual}`);

        if(userInputs.userName.isInvalid || userInputs.login.isInvalid || firstPasswdIsInvalide || !passwdIsEqual){
            console.log("SAVE FAILURE!!!");

            this.setState({alertShow: true});

            return;
        }

        let transferObject = {
            "user_name": userInputs.userName.value,
            "work_group": userInputs.workGroup.value,
            "user_login": userInputs.login.value,
            "user_password": userInputs.firstPassword.value,
        };

        console.log("SENDING object with information to server -->");
        console.log(JSON.stringify(transferObject));

        this.props.socketIo.emit("add new user", {
            actionType: "create",
            arguments: transferObject,
        });

        this.handlerClose();
    }

    render(){
        let alertMessage = "Вероятно вы забыли заполнить некоторые поля или заданные пользователем параметры не прошли валидацию.";

        return(
            <Modal show={this.props.show} onHide={this.handlerClose}>
                <Modal.Header closeButton>
                    <Modal.Title>{this.props.children}</Modal.Title>
                </Modal.Header>
                <Modal.Body>
                    <Form>
                        <Form.Group controlId="userName">
                            <Form.Label>Имя пользователя</Form.Label>
                            <Form.Control 
                                control="text" 
                                onChange={this.handlerUserInput}
                                isValid={this.state.formElements.userName.isValid} 
                                isInvalid={this.state.formElements.userName.isInvalid} />
                        </Form.Group>
                        <Form.Group controlId="workGroup">
                            <Form.Label>Рабочая группа</Form.Label>
                            <Form.Control as="select" onChange={this.handlerUserInput}>
                                {this.props.listWorkGroup.map(group => {
                                    return <option key={this.getKey(`group_${group}`)}>{group}</option>;
                                })}
                            </Form.Control>
                        </Form.Group>
                        <Form.Group controlId="login">
                            <Form.Label>Логин пользователя</Form.Label>
                            <Form.Control 
                                control="text" 
                                onChange={this.handlerUserInput}
                                isValid={this.state.formElements.login.isValid} 
                                isInvalid={this.state.formElements.login.isInvalid} />
                        </Form.Group>
                        <Form.Group controlId="firstPassword">
                            <Form.Label>Пароль пользователя</Form.Label>
                            <Form.Control 
                                type="password" 
                                placeholder="введите пароль" 
                                onChange={this.handlerUserInput}
                                isValid={this.state.formElements.firstPassword.isValid} 
                                isInvalid={this.state.formElements.firstPassword.isInvalid} />
                        </Form.Group>
                        <Form.Group controlId="secondPassword">
                            <Form.Control 
                                type="password" 
                                placeholder="подтвердите пароль" 
                                onChange={this.handlerUserInput}
                                isValid={this.state.formElements.secondPassword.isValid} 
                                isInvalid={this.state.formElements.secondPassword.isInvalid} />
                        </Form.Group>
                    </Form>
                </Modal.Body>
                <Modal.Footer>
                    <ModalAlertDangerMessage show={this.state.alertShow} onClose={this.alertClose} message={alertMessage}>
                            Ошибка при сохранении!
                    </ModalAlertDangerMessage>
                    <Button variant="outline-secondary" onClick={this.handlerClose}>закрыть</Button>
                    <Button variant="outline-primary" onClick={this.handlerSave}>сохранить</Button>
                </Modal.Footer>
            </Modal>
        );
    }
}

ModalWindowAddEditUser.propTypes ={
    show: PropTypes.bool.isRequired,
    onHide: PropTypes.func.isRequired,
    children: PropTypes.string.isRequired,
    socketIo: PropTypes.object.isRequired,
    listWorkGroup: PropTypes.array.isRequired,
};
