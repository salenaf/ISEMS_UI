/**
 * Модуль формирования модального окна для изменения дефолтного
 * пароля администратора
 * 
 * Версия 0.2, дата релиза 24.12.2019
 */

"use strict";

import React from "react";
import { Button, Modal, Form } from "react-bootstrap";
import PropTypes from "prop-types";

import { helpers } from "../common_helpers/helpers";
import { ModalAlertDangerMessage } from "../commons/modalAlertMessage.jsx";

export { ModalWindowChangeAdminPasswd };

class ModalWindowChangeAdminPasswd extends React.Component {
    constructor(props){
        super(props);

        this.alertClose = this.alertClose.bind(this);
        this.windowShow = this.windowShow.bind(this);
        this.handlerSave = this.handlerSave.bind(this);
        this.handlerClose = this.handlerClose.bind(this);
        this.handlerUserInput = this.handlerUserInput.bind(this);

        this.state = {
            alertShow: false,
            modalWindowShow: true,
            formElements: {
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
            },
        };
    }

    windowShow(){
        this.setState({modalWindowShow: true});
    }

    handlerClose(){
        this.setState({modalWindowShow: false});
    }

    handlerSave(){
        const firstPasswd = this.state.formElements.firstPassword.value;
        const secondPasswd = this.state.formElements.secondPassword.value;

        if(firstPasswd !== secondPasswd){
            this.setState({ alertShow: true });

            return;
        }

        this.props.socketIo.emit("change password", {
            actionType: "change password",
            arguments: { 
                "user_login": this.props.login,
                "user_password": firstPasswd, 
            },
        });

        this.handlerClose();
    }

    alertClose(){
        this.setState({alertShow: false});
    }

    handlerUserInput(event){
        const value = event.target.value;
        const elementName = event.target.id;

        const elemType = {
            firstPassword: "stringPasswd",
            secondPassword: "stringPasswd",
        };

        let objUpdate = Object.assign({}, this.state);
        if(objUpdate.formElements[elementName] === "undefined"){
            return;
        }

        objUpdate.formElements[elementName].value = value;

        if(helpers.checkInputValidation({name: elemType[elementName], value: value})){
            objUpdate.formElements[elementName].isValid = true;
            objUpdate.formElements[elementName].isInvalid = false;
        } else {
            objUpdate.formElements[elementName].isValid = false;
            objUpdate.formElements[elementName].isInvalid = true;
        }

        this.setState( objUpdate );
    }

    render(){
        let alertMessage = "Пароль не прошел валидацию. ";

        if(!this.props.passIsDefault){
            return <span></span>;
        }

        return <Modal show={this.state.modalWindowShow} onHide={this.handlerClose}>
            <Modal.Header closeButton>
                <Modal.Title>Смена пароля</Modal.Title>
            </Modal.Header>
            <Modal.Body>
                <p>
                Для пользователя Администратор используется стандартный пароль, формируемый при первом запуске
                приложения. Для безопасного использования приложения необходимо сменить пароль на более стойкий.
                </p>
                <Form>
                    <Form.Group controlId="firstPassword">
                        <Form.Label>Новый пароль пользователя Администратор</Form.Label>
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
                <ModalAlertDangerMessage show={this.state.alertShow} onClose={this.alertClose} message={alertMessage}>
                    Ошибка при сохранении!
                </ModalAlertDangerMessage>
            </Modal.Body>
            <Modal.Footer>
                <Button variant="outline-secondary" onClick={this.handlerClose}>закрыть</Button>
                <Button variant="outline-primary" onClick={this.handlerSave}>сохранить</Button>
            </Modal.Footer>
        </Modal>;
    }
}

ModalWindowChangeAdminPasswd.propTypes = {
    login: PropTypes.string.isRequired,
    passIsDefault: PropTypes.bool,
    socketIo: PropTypes.object.isRequired,
};