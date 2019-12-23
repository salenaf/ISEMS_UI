/**
 * Модуль формирования модального окна добавления нового пользователя
 * 
 * Версия 0.2, дата релиза 23.12.2019
 */

"use strict";

import React from "react";
import { Button, Modal, Form } from "react-bootstrap";
import PropTypes from "prop-types";

import { helpers } from "../common_helpers/helpers";
import { ModalAlertDangerMessage } from "../commons/modalAlertMessage.jsx";

export { ModalWindowAddEdit };

class ModalWindowAddEdit extends React.Component {
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

        let objUpdate = Object.assign({}, this.state);
        for(let elem in objUpdate.formElements){
            if (elem === "workGroup") continue;
            objUpdate.formElements[elem].isValid = false;
            objUpdate.formElements[elem].isInvalid =false;    
        }
        objUpdate.alertShow = false;
        this.setState( objUpdate );
    }

    handlerSave(){
        let userInputs = this.state.formElements;
        let firstPasswdIsInvalide = userInputs.firstPassword.isValid;
        let passwdIsEqual = (userInputs.firstPassword.value.localeCompare(userInputs.secondPassword.value) === 0);
        
        //если пароли не равны
        if (!passwdIsEqual){
            let objUpdate = Object.assign({}, this.state);
            
            objUpdate.formElements.firstPassword.isInvalid = true;
            objUpdate.formElements.secondPassword.isInvalid = true;

            this.setState( objUpdate );
        }

        let transferObject = {
            "user_name": userInputs.userName.value,
            "work_group": userInputs.workGroup.value,
            "user_login": userInputs.login.value,
            "user_password": userInputs.firstPassword.value,
        };
        let typeEvent = "add new user";
        let at = "create";

        if(!this.props.isAddUser){
            if(userInputs.userName.value.length === 0){
                if(!firstPasswdIsInvalide || !passwdIsEqual){
                    this.setState({alertShow: true});

                    return;
                }
                
                transferObject.user_name = this.props.userSettings.name;
            } else {
                if(!userInputs.userName.isValid || !firstPasswdIsInvalide || !passwdIsEqual){
                    this.setState({alertShow: true});

                    return;
                }            
            }

            transferObject.user_login = this.props.userSettings.login;
            typeEvent = "update user";
            at = "edit";
        } else {
            if(!userInputs.userName.isValid || !userInputs.login.isValid || !firstPasswdIsInvalide || !passwdIsEqual){
                this.setState({alertShow: true});
    
                return;
            }

            transferObject.user_login = userInputs.login.value;
        }

        this.props.socketIo.emit(typeEvent, {
            actionType: at,
            arguments: transferObject,
        });

        this.handlerClose();
    }

    addOrEdit(){
        let settings = {
            windowHeader: "Добавить нового пользователя",
            isReadOnly: "",
            defaultValue: "",
        };

        if (!this.props.isAddUser){
            settings = {
                windowHeader: "Изменить настройки пользователя",
                isReadOnly: " true",
                defaultValue: {
                    defaultUserName: this.props.userSettings.name,
                    defaultUserLogin: this.props.userSettings.login,
                    defaultUserGroup: this.props.userSettings.group,
                },
            };
        }

        return settings;
    }

    render(){
        let alertMessage = "Вероятно вы забыли заполнить некоторые поля или заданные пользователем параметры не прошли валидацию.";      
        let modalSettings = this.addOrEdit();
        let defaultValueGroup = "";
        if(!this.props.isAddUser){
            defaultValueGroup = this.props.userSettings.group;
        }

        return(
            <Modal show={this.props.show} onHide={this.handlerClose}>
                <Modal.Header closeButton>
                    <Modal.Title>{modalSettings.windowHeader}</Modal.Title>
                </Modal.Header>
                <Modal.Body>
                    <Form>
                        <Form.Group controlId="userName">
                            <Form.Label>Имя пользователя</Form.Label>
                            <Form.Control 
                                control="text" 
                                onChange={this.handlerUserInput}
                                defaultValue={modalSettings.defaultValue.defaultUserName}
                                isValid={this.state.formElements.userName.isValid} 
                                isInvalid={this.state.formElements.userName.isInvalid} />
                        </Form.Group>
                        <Form.Group controlId="workGroup">
                            <Form.Label>Рабочая группа</Form.Label>
                            <Form.Control as="select" defaultValue={defaultValueGroup} onChange={this.handlerUserInput}>
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
                                readOnly={modalSettings.isReadOnly}
                                defaultValue={modalSettings.defaultValue.defaultUserLogin}
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

ModalWindowAddEdit.propTypes = {
    show: PropTypes.bool.isRequired,
    onHide: PropTypes.func.isRequired,
    isAddUser: PropTypes.bool,
    userSettings: PropTypes.object,
    socketIo: PropTypes.object.isRequired,
    listWorkGroup: PropTypes.array.isRequired,
};

