/**
 * Модуль формирующий основную таблицу на странице
 * 
 * Версия 0.21, дата релиза 11.12.2019
 */

"use strict";

import React from "react";
import ReactDOM from "react-dom";

import { Button, Table } from "react-bootstrap";
import PropTypes from "prop-types";

import { ModalWindowAddEditUser } from "./setting_users_page/modalWindowAddEditUser.jsx";
import { ModalWindowConfirmMessage } from "./commons/modalWindowConfirmMessage.jsx";

class HeadTable extends React.Component {
    constructor(props){
        super(props);

        this.handleShow = this.handleShow.bind(this);
        this.handleClose = this.handleClose.bind(this);

        this.state = {
            modalShow: false,
        };
    }

    handleShow() {
        this.setState({ modalShow: true });
    }

    handleClose() {
        this.setState({ modalShow: false });
    }

    render(){
        let accessRights = this.props.accessRights;        
        let isDisabled = (accessRights.create.status)? "": "disabled";

        /**
 * 
 * Сделать отрисовку информационных сообщений
 * но это нужно делать гдето в заголовке станицы или меню
 * вобщем в том разделе который постоянно находится на любой странице 
 * 
 * 
 */

        return (
            <thead>
                <tr>
                    <th>Логин</th>
                    <th>Имя пользователя</th>
                    <th>Рабочая группа</th>
                    <th>Дата создания</th>
                    <th>Дата изменения</th>
                    <th className={"text-right"}>
                        <Button variant="outline-primary" onClick={this.handleShow} disabled={isDisabled}>
                            добавить
                        </Button>
                        <ModalWindowAddEditUser
                            socketIo={this.props.socketIo} 
                            show={this.state.modalShow} 
                            onHide={this.handleClose} 
                            listWorkGroup={this.props.listWorkGroup}>
                            Добавить нового пользователя
                        </ModalWindowAddEditUser>
                    </th>
                </tr>
            </thead>
        );
    }
}

HeadTable.propTypes = {
    accessRights: PropTypes.object.isRequired,
    listWorkGroup: PropTypes.array.isRequired,
};

class ButtonEdit extends React.Component {
    render(){
        let login = this.props.login;
        let accessRights = this.props.accessRights;

        let isDisabled;

        if((login === "administrator") || !accessRights.edit.status) {
            isDisabled = "disabled";
        }

        return <Button variant="outline-dark" size="sm" disabled={isDisabled}>редактировать</Button>;
    }
}

ButtonEdit.propTypes = {
    login: PropTypes.string.isRequired,
    accessRights: PropTypes.object.isRequired,
};

class ButtonDelete extends React.Component {
    render(){
        let login = this.props.login;
        let accessRights = this.props.accessRights;

        let isDisabled;

        if((login === "administrator") || !accessRights.delete.status) {
            isDisabled = "disabled";
        }

        return (
            <Button 
                onClick={this.props.handler}
                variant="outline-danger" 
                size="sm" 
                disabled={isDisabled}>
            удалить
            </Button>);
    }
}

ButtonDelete.propTypes = {
    login: PropTypes.string.isRequired,
    accessRights: PropTypes.object.isRequired,
    handler: PropTypes.func.isRequired,
};

class BodyTable extends React.Component {
    constructor(props){
        super(props);

        this.addUsersList = this.addUsersList.bind(this);
    }

    addUsersList(){
        let users = this.props.users;

        let adminUser = [],
            othersUser = [];

        let dateFormatter = new Intl.DateTimeFormat("ru", {
            year: "numeric",
            month: "numeric",
            day: "numeric",
        });

        let dateTimeFormatter = new Intl.DateTimeFormat("ru", {
            hour: "numeric",
            minute: "numeric",
            second: "numeric",
            year: "numeric",
            month: "numeric",
            day: "numeric",
        });

        users.forEach(user => {          
            let key = user.userID;
            let elem = <tr key={`tr_${key}`}>
                <td key={`td_login_${key}`}>{user.login}</td>
                <td key={`td_user_name_${key}`}>{user.userName}</td>
                <td key={`td_group_${key}`}>{user.group}</td>
                <td key={`td_date_register_${key}`}>{dateFormatter.format(user.dateRegister)}</td>
                <td key={`td_date_change_${key}`}>{dateTimeFormatter.format(user.dateChange)}</td>
                <td className={"text-right"} key={`td_buttons_${key}`}>
                    <ButtonEdit login={user.login} accessRights={this.props.accessRights} key={`button_edit_${key}`}/>
                    &nbsp;&nbsp;
                    <ButtonDelete 
                        login={user.login} 
                        handler={this.props.handlerButtonDelete.bind(this, key, user.login)} 
                        accessRights={this.props.accessRights} 
                        key={`button_del_${key}`}/>
                </td>
            </tr>;

            if(user.login === "administrator"){
                adminUser.push(elem);
            } else {
                othersUser.push(elem);
            }
        });

        adminUser.push(othersUser);

        return adminUser;
    }

    render(){
        return (
            <tbody>{this.addUsersList()}</tbody>
        );
    }
}

BodyTable.propTypes = {
    users: PropTypes.array.isRequired,
    accessRights: PropTypes.object.isRequired,
    handlerButtonDelete: PropTypes.func.isRequired,
};

class CreateTable extends React.Component {
    constructor(props){
        super(props);
       
        this.addListeners = this.addListeners.bind(this);        
        this.addOrUpdateNewUser = this.addOrUpdateNewUser.bind(this);
        this.deleteUser = this.deleteUser.bind(this);

        this.handlerModalConfirmShow = this.handlerModalConfirmShow.bind(this);
        this.handlerModalConfirmClose = this.handlerModalConfirmClose.bind(this);

        this.sendMsgDeleteUser = this.sendMsgDeleteUser.bind(this);

        this.state = {
            userList: this.props.mainInformation,
            modalConfirm: {
                show: false,
                userID: "",
                userLogin: "",
            },
        };

        this.addListeners();
    }
  
    handlerModalConfirmShow(userID, userLogin){
        let objState = Object.assign({}, this.state);
        objState.modalConfirm = {
            show: true,
            userID: userID,
            userLogin: userLogin,
        };

        this.setState(objState);
    }

    handlerModalConfirmClose(){
        let objState = Object.assign({}, this.state);
        objState.modalConfirm = {
            show: false,
            userID: "",
            userLogin: "",
        };

        this.setState(objState);    
    }

    addOrUpdateNewUser(newUser){
        let objNewUser = JSON.parse(newUser);

        let objState = Object.assign({}, this.state);

        objState.userList.push({
            userID: objNewUser.userID,
            userName: objNewUser.userName,
            login: objNewUser.login,
            group: objNewUser.group,
            dateRegister: objNewUser.dateRegister,
            dateChange: objNewUser.dateChange,
        });

        this.setState(objState);    
    }

    deleteUser(delUser){
        let userID = JSON.parse(delUser).userID;

        let newUserList = this.state.userList.filter(item => item.userID !== userID);

        let objState = Object.assign({}, this.state);
        objState.userList = newUserList;

        this.setState(objState);
    }

    sendMsgDeleteUser(userID){
        this.props.socketIo.emit("delete user", {
            actionType: "delete",
            arguments: {
                userID: userID,
            },
        });

        this.handlerModalConfirmClose();
    }

    addListeners(){
        let listEvents = {
            "add new user": newUser => {
                this.addOrUpdateNewUser(newUser);
            },
            "update user": updateUser => {
                this.addOrUpdateNewUser(updateUser);
            },
            "del selected user": delUser => {
                this.deleteUser(delUser);
            },
        };

        for(let event in listEvents){
            this.props.socketIo.on(event, listEvents[event]);
        }
    }

    render(){
        return (
            <div>
                <h4 className="text-left text-uppercase">управление пользователями</h4>
                <Table striped hover>
                    <HeadTable socketIo={this.props.socketIo} accessRights={this.props.accessRights} listWorkGroup={this.props.listWorkGroup}/>
                    <BodyTable users={this.state.userList} accessRights={this.props.accessRights} handlerButtonDelete={this.handlerModalConfirmShow}/>
                </Table>
                <ModalWindowConfirmMessage
                    show={this.state.modalConfirm.show} 
                    onHide={this.handlerModalConfirmClose}
                    userID={this.state.modalConfirm.userID}
                    handlerConfirm={this.sendMsgDeleteUser}
                    msgTitle={"Удаление"}
                    msgBody={`Вы действительно хотите удалить пользователя ${this.state.modalConfirm.userLogin}?`}
                />
            </div>
        );
    }
}

CreateTable.propTypes = {
    socketIo: PropTypes.object.isRequired,
    mainInformation: PropTypes.array.isRequired,
    accessRights: PropTypes.object.isRequired,
    listWorkGroup: PropTypes.array.isRequired,
};

ReactDOM.render(<CreateTable 
    socketIo={socket}
    mainInformation={receivedFromServerMain} 
    accessRights={receivedFromServerAccess} 
    listWorkGroup={receivedFromServerListWorkGroup} />, document.getElementById("field_information"));