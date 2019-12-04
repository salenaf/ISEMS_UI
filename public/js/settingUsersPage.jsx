/**
 * Модуль формирующий основную таблицу на странице
 * 
 * Версия 0.1, дата релиза 28.11.2019
 */

"use strict";

import React from "react";
import ReactDOM from "react-dom";

import { Alert, Button, Table } from "react-bootstrap";
import PropTypes from "prop-types";

import { helpers } from "./common_helpers/helpers";
import showNotifyMessage from "./common_helpers/showNotifyMessage";
import { ModalWindowAddEditUser } from "./setting_users_page/modalWindowAddEditUser.jsx";

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

        return <Button variant="outline-danger" size="sm" disabled={isDisabled}>удалить</Button>;
    }
}

ButtonDelete.propTypes = {
    login: PropTypes.string.isRequired,
    accessRights: PropTypes.object.isRequired,
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
                    <ButtonEdit login={user.login} accessRights={this.props.accessRights} key={`button_edit_${key}`}/>&nbsp;
                    <ButtonDelete login={user.login} accessRights={this.props.accessRights} key={`button_del_${key}`}/>
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
};

/**
 * {
  managementUsers   dateRegister: 1550043504498,
  managementUsers   dateChange: 1550043504498,
  managementUsers   group: 'administrator',
  managementUsers   userName: 'Администратор',
  managementUsers   login: 'administrator'
  managementUsers } +1ms

    managementUsers {
  managementUsers   create: {
  managementUsers     id: 'c0234594174f3051d8177822554ea5d1',
  managementUsers     status: true,
  managementUsers     description: 'создание'
  managementUsers   },
  managementUsers   edit: {
  managementUsers     id: '20398ecd2be259828494872d98d71de7',
  managementUsers     status: true,
  managementUsers     description: 'редактирование'
  managementUsers   },
  managementUsers   delete: {
  managementUsers     id: '76775b639fd7626ab307e9ffed7b8a9c',
  managementUsers     status: true,
  managementUsers     description: 'удаление'
  managementUsers   }
  managementUsers } +0ms
 */

class CreateTable extends React.Component {
    constructor(props){
        super(props);
       
        this.tableUpdate = this.tableUpdate.bind(this);

        this.state = {
            userList: this.props.mainInformation,
        };
    }

    userListUpdate(){
        this.props.socketIo.on("update user list", (list) => {
            console.log("reseived event 'update user list'");
            console.log(list);
        });
    }

    tableUpdate(e){
        setTimeout(() => {
            let objState = Object.assign({}, this.state);

            objState.userList.push({
                userID: "je9j9cj9j93939hfh84444545",
                dateRegister: Date.now(),
                dateChange: Date.now(),
                group: "all_user",
                userName: "Добавлен новый пользователь",
                login: "addnewuser",
            });

            this.setState(objState);

            console.log(this.state.userList);
        }, 5000);
    }

    render(){
        //        this.tableUpdate();
        this.userListUpdate();

        return (
            <div>
                <h4 className="text-left text-uppercase">управление пользователями</h4>
                <Table striped hover>
                    <HeadTable socketIo={this.props.socketIo} accessRights={this.props.accessRights} listWorkGroup={this.props.listWorkGroup}/>
                    <BodyTable users={this.state.userList} accessRights={this.props.accessRights}/>
                </Table>
            </div>
        );
    }
}

CreateTable.propTypes = {
    socketIo: PropTypes.object,
    mainInformation: PropTypes.array.isRequired,
    accessRights: PropTypes.object.isRequired,
    listWorkGroup: PropTypes.array.isRequired,
};

ReactDOM.render(<CreateTable 
    socketIo={socket}
    mainInformation={receivedFromServerMain} 
    accessRights={receivedFromServerAccess} 
    listWorkGroup={receivedFromServerListWorkGroup} />, document.getElementById("field_information"));