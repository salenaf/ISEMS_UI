/**
 * Модуль формирования модального окна для изменения дефолтного
 * пароля администратора
 * 
 * Версия 0.1, дата релиза 17.12.2019
 */

"use strict";

import React from "react";
import { Button, Modal, Form } from "react-bootstrap";
import PropTypes from "prop-types";

import { ModalAlertDangerMessage } from "../commons/modalAlertMessage.jsx";

export { ModalWindowChangeAdminPasswd };

class ModalWindowChangeAdminPasswd extends React.Component {
    constructor(props){
        super(props);

        this.windowShow = this.windowShow.bind(this);
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

    alertClose(){
        this.setState({alertClose: false});
    }

    handlerUserInput(){

    }

    render(){
        let alertMessage = "Заданный пароль не прошел валидацию.";

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
            </Modal.Body>
            <Modal.Footer>
                <ModalAlertDangerMessage show={this.state.alertShow} onClose={this.alertClose} message={alertMessage}>
                    Ошибка при сохранении!
                </ModalAlertDangerMessage>
                <Button variant="outline-secondary" onClick={this.handlerClose}>закрыть</Button>
                <Button variant="outline-primary" onClick={this.handlerSave}>сохранить</Button>
            </Modal.Footer>
        </Modal>;
    }
}

ModalWindowChangeAdminPasswd.propTypes = {
    login: PropTypes.string.isRequired,
    passIsDefault: PropTypes.bool,
};