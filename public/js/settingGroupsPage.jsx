/**
 * Модуль формирующий основную таблицу на странице
 * 
 * Версия 0.1, дата релиза 31.01.2019
 */

"use strict";

import React from "react";
import ReactDOM from "react-dom";
import { Alert, Button, Table } from "react-bootstrap";
import PropTypes from "prop-types";

import { helpers } from "./common_helpers/helpers";
import ModalWindowAddNewGroup from "./setting_groups_page/modalWindowAddNewGroup.jsx";

//перечисление типов действий доступных для администратора
class CreateListCategoryMain extends React.Component {
    render() {
        let itemName = " ";
        if(typeof this.props.list.name !== "undefined"){
            itemName = <strong>{this.props.list.name}</strong>;
        }

        let liNoMarker = { "listStyleType": "none" };

        let isMenuItem = this.props.parameters.typeItem === "menu_items";
        let moreThanTree = this.props.parameters.countSend === 3;

        let createCategoryValue = <CreateCategoryValue
            list={this.props.list}
            listOtherGroup={this.props.listOtherGroup}
            parameters={this.props.parameters} />;

        if (this.props.parameters.group === "administrator") {
            if (this.props.parameters.first) {
                return <ul className="text-left">
                    {itemName}
                    <ul style={liNoMarker}>
                        {createCategoryValue}
                    </ul>
                </ul>;
            }

            if (isMenuItem || moreThanTree) {
                return <div>
                    {itemName}
                    <ul style={liNoMarker}>
                        {createCategoryValue}
                    </ul>
                </div>;
            }

            return <React.Fragment>
                {itemName}
                {createCategoryValue}
            </React.Fragment>;
        }

        if ((this.props.parameters.first) || isMenuItem || moreThanTree) {
            return <div>&nbsp;{createCategoryValue}</div>;
        }

        return createCategoryValue;
    }
}

CreateListCategoryMain.propTypes = {
    list: PropTypes.object.isRequired,
    listOtherGroup: PropTypes.object.isRequired,
    parameters: PropTypes.object.isRequired
};

//перечисление значений 
class CreateCategoryValue extends React.Component {
    render() {
        let arrItems = [];
        let parameters = {
            "group": this.props.parameters.group,
            "typeItem": this.props.parameters.typeItem,
            "first": false
        };

        for (let item in this.props.list) {
            if (item === "name" || item === "id") continue;

            if (typeof this.props.list[item].status === "undefined") {
                parameters.countSend = this.props.parameters.countSend + 1;

                arrItems.push(
                    <CreateListCategoryMain
                        list={this.props.list[item]}
                        listOtherGroup={this.props.listOtherGroup}
                        parameters={parameters}
                        key={`return_${this.props.list[item].id}`} />);

                continue;
            }

            if (this.props.parameters.group === "administrator") {
                arrItems.push(
                    <div key={`div_${this.props.list[item].id}`}>
                        <input
                            type="checkbox"
                            disabled="disabled"
                            defaultChecked={this.props.list[item].status}
                            name="checkbox_administrator" />&nbsp;
                        {this.props.list[item].description}
                    </div>);

                continue;
            }

            let groupObj = this.props.listOtherGroup[this.props.parameters.group][this.props.list[item].id];
            arrItems.push(
                <div key={`div_${groupObj.keyID}`}>
                    <input
                        type="checkbox"
                        defaultChecked={groupObj.status}
                        name={`checkbox_${this.props.parameters.group}`} />&nbsp;
                </div>);
        }

        return arrItems;
    }
}

CreateCategoryValue.propTypes = {
    list: PropTypes.object.isRequired,
    listOtherGroup: PropTypes.object.isRequired,
    parameters: PropTypes.object.isRequired
};

//кнопка 'добавить' новую группу
class ButtonAddGroup extends React.Component {
    constructor(props) {
        super(props);

        this.handleShow = this.handleShow.bind(this);
    }

    handleShow() {
        this.props.handlerShowModal();
    }

    render() {
        let disabledCreate = (this.props.access.create.status) ? "" : "disabled";

        return <Button
            variant="outline-primary"
            size="sm"
            onClick={this.handleShow.bind(this)}
            disabled={disabledCreate} >
                добавить
        </Button>;
    }
}

ButtonAddGroup.propTypes = {
    access: PropTypes.object.isRequired,
    handlerShowModal: PropTypes.func.isRequired,
    groupListElement: PropTypes.object.isRequired
};

//кнопка 'сохранить изменение параметров группы'
class ButtonEdit extends React.Component {
    render() {
        return <Button
            variant="outline-dark"
            size="sm"
            onClick={this.props.handleUpdateGroup}
            disabled={this.props.disabledEdit}>
                сохранить
        </Button>;
    }
}

ButtonEdit.propTypes = { 
    disabledEdit: PropTypes.string.isRequired,
    handleUpdateGroup: PropTypes.func.isRequired,
};

//кнопка 'удалить группу'
class ButtonDelete extends React.Component {
    render() {
        return <Button
            variant="outline-danger"
            size="sm"
            onClick={this.props.handleDeleteGroup}
            disabled={this.props.disabledDelete}>
                удалить
        </Button>;
    }
}

ButtonDelete.propTypes = { 
    disabledDelete: PropTypes.string.isRequired,
    handleDeleteGroup: PropTypes.func.isRequired,
};

//перечисление групп
class EnumGroupName extends React.Component {
    constructor(props){
        super(props);
    }

    render() {
        let styleGroupName = {
            "paddingBottom": "13px"
        };

        let disabledEdit = (!this.props.accessRights.edit.status) ? "disabled" : "";
        let disabledDelete = (!this.props.accessRights.delete.status) ? "disabled" : "";

        let bEdit, bDel;
        let textCenter = "text-left";
        let butAddGroup = <ButtonAddGroup
            access={this.props.accessRights}
            handlerShowModal={this.props.handlerShowModal}
            groupListElement={this.props.listAdmin.elements} />;

        let arrGroup = this.props.groupsName.map(group => {
            if (group.groupName.toLowerCase() !== "administrator") {
                bDel = <ButtonDelete disabledDelete={disabledDelete} handleDeleteGroup={this.props.handleDeleteGroup.bind(this, group.groupName)} />;
                bEdit = <ButtonEdit disabledEdit={disabledEdit} handleUpdateGroup={this.props.handleUpdateGroup.bind(this, group.groupName)} />;
                textCenter = "text-center";
                styleGroupName.paddingBottom = "";
                butAddGroup = "";
            }

            return <th className={textCenter} style={styleGroupName} key={`group_name_${group.groupName}`}>
                {group.groupName}&nbsp;
                <div>{butAddGroup}&nbsp;{bEdit}&nbsp;{bDel}</div>
            </th>;
        });

        return arrGroup;
    }
}

EnumGroupName.propTypes = {
    groupsName: PropTypes.array.isRequired,
    listAdmin: PropTypes.object.isRequired,
    accessRights: PropTypes.object.isRequired,
    handlerShowModal: PropTypes.func.isRequired,
    handleDeleteGroup: PropTypes.func.isRequired,
    handleUpdateGroup: PropTypes.func.isRequired,
};

//вывод даты создания группы
class ShowDateCreateGroup extends React.Component {
    render() {
        let dateCreate = this.props.groupsName.map(group => {
            let text = "";
            let textCenter = "text-center";

            if (group.groupName === "administrator") {
                text = "группа создана: ";
                textCenter = "text-left";
            }

            let [dateString,] = helpers.getDate(group.dateRegister).split(" ");
            let [year, month, day] = dateString.split("-");
            let dateCreate = `${day}.${month}.${year}`;

            return <th className={textCenter} key={`date_create_${group.groupName}`}>
                {`${text} ${dateCreate}`}
            </th>;
        });

        return dateCreate;
    }
}

ShowDateCreateGroup.propTypes = {
    groupsName: PropTypes.array.isRequired,
};

class CreateBodyElement extends React.Component {
    createElement() {
        let { groupsName, listAdmin, listOtherGroup } = this.props;


        let arrTmp = [];
        for (let item in listAdmin.elements) {           
            let arrTd = groupsName.map(group => {
                let listCategoryParameters = {
                    "group": group.groupName,
                    "countSend": 0,
                    "typeItem": item,
                    "first": true
                };

                if(group.groupName === "administrator"){
                    return <td key={`td_${group.groupName}_${listAdmin.elements[item].id}`}>
                        <CreateListCategoryMain
                            list={listAdmin.elements[item]}
                            listOtherGroup={listOtherGroup}
                            parameters={listCategoryParameters}
                            key={listAdmin.elements[item].id} />
                    </td>;    
                }

                return <td key={`td_${group.groupName}_${listAdmin.elements[item].id}`}>
                    <CreateListCategoryMain
                        list={listAdmin.elements[item]}
                        listOtherGroup={listOtherGroup}
                        parameters={listCategoryParameters}
                        key={listAdmin.elements[item].id} />
                </td>;
            });

            arrTmp.push(<tr key={`tr_${listAdmin.elements[item].id}`}>{arrTd}</tr>);
        }

        return arrTmp;
    }

    render() {
        let arrBody = this.createElement.call(this);

        return arrBody;
    }
}

CreateBodyElement.propTypes = {
    groupsName: PropTypes.array.isRequired,
    listAdmin: PropTypes.object.isRequired,
    listOtherGroup: PropTypes.objectOf(PropTypes.object).isRequired,
};

//создание основной таблицы
class CreateTable extends React.Component {
    constructor(props) {
        super(props);

        this.state = {
            modalWindowAddShow: false,
            groupsName: this.getGroupsName(),
        };

        this.groupsAdministrator = this.props.mainInformation.administrator;        
        this.listOtherGroup = this.changeListGroupsInformation(this.props.mainInformation);

        this.handleShow = this.handleShow.bind(this);
        this.handleClose= this.handleClose.bind(this);
        this.addNewGroup = this.addNewGroup.bind(this);
        this.updateGroup = this.updateGroup.bind(this);   
        this.deleteGroup = this.deleteGroup.bind(this);
        this.handleAddNewGroup = this.handleAddNewGroup.bind(this);
        this.handleUpdateGroup = this.handleUpdateGroup.bind(this);
        this.handleDeleteGroup = this.handleDeleteGroup.bind(this);

        this.addListeners();
    }

    handleShow() {
        this.setState({ modalWindowAddShow: true });
    }

    handleClose() {
        this.setState({ modalWindowAddShow: false });
    }

    handleAddNewGroup(data) {
        this.props.socketIo.emit("add new group", {
            actionType: "create",
            arguments: data
        });
    }

    handleDeleteGroup(groupName){
        this.props.socketIo.emit("delete group", {
            actionType: "create",
            arguments: {
                groupName: groupName,
            },
        });
    }

    handleUpdateGroup(data){
        console.log("func 'handleUpdateGroup', START...");
        console.log(`update information for group: ${data}`);
        console.log("нужны еще данные по параметрам которые будут изменены");

    }

    addListeners(){
        let listEvents = {
            "add new group": newGroup => {
                this.addNewGroup(newGroup);
            },
            "update group": updateGroupInfo => {
                this.updateGroup(updateGroupInfo);
            },
            "del selected group": delGroup => {
                this.deleteGroup(delGroup);
            },
        };

        for(let event in listEvents){
            this.props.socketIo.on(event, listEvents[event]);
        }
    }

    addNewGroup(newGroup){
        console.log("function 'addNewGroup', START...");

        let newGroupObj = JSON.parse(newGroup);
        let groupName = newGroupObj.group_name;

        let newObj = {};
        newObj[groupName]={
            "date_register": newGroupObj["date_register"],
            "elements": newGroupObj[groupName],
        };
        let convertObj = this.changeListGroupsInformation(newObj);

        let stateCopy = Object.assign({}, this.state);
        stateCopy.groupsName.push({
            groupName: groupName,
            dateRegister: newGroupObj["date_register"],
        });

        console.log(`GROUP NAME: ${groupName}`);
        console.log(stateCopy);

        this.listOtherGroup = Object.assign(this.listOtherGroup, convertObj);

        console.log(this.listOtherGroup);

        this.setState({stateCopy});

        console.log("function 'addNewGroup', END...");
    }

    updateGroup(updateGroupInfo){
        console.log("function 'updateGroup', START...");
    }

    deleteGroup(delGroup){
        console.log("function 'deleteGroup', START...");
    }

    getGroupsName() {
        let groups = Object.keys(this.props.mainInformation);
        groups.sort();

        let list = [{
            groupName: "administrator",
            dateRegister: this.props.mainInformation["administrator"].date_register,
        }];
        let groupsOtherAdmin = groups.filter(item => item !== "administrator");

        for(let item of groupsOtherAdmin){
            list.push({
                groupName: item,
                dateRegister: this.props.mainInformation[item].date_register,
            });
        }

        return list;
    }

    changeListGroupsInformation(listOtherGroup){
        let obj = {};
        let getElementObject = (groupName, listElement, listAdmin) => {
            for (let key in listAdmin) {              
                if ((typeof listAdmin[key] === "string") || (typeof listAdmin[key] === "number")) continue;
                if ("status" in listAdmin[key]) {
                    obj[groupName][listAdmin[key].id] = {
                        keyID: listElement[key].id,
                        status: listElement[key].status,
                    };

                    continue;
                }

                getElementObject(groupName, listElement[key], listAdmin[key]);
            }
        };

        for(let groupName in listOtherGroup){
            obj[groupName] = {};

            if(groupName === "administrator") continue;

            getElementObject(groupName, listOtherGroup[groupName].elements, this.groupsAdministrator.elements);
        }

        return obj;
    }

    showAlerts() {
        return <Alert variant="danger">Message</Alert>;
    }

    render() {
        return <div>
            <h4 className="text-left">Управление группами</h4>
            <Table striped hover>
                <thead>
                    <tr>
                        <ShowDateCreateGroup groupsName={this.state.groupsName} />
                    </tr>
                    <tr>
                        <EnumGroupName
                            groupsName={this.state.groupsName}
                            listAdmin={this.groupsAdministrator}
                            accessRights={this.props.accessRights}
                            handleDeleteGroup={this.handleDeleteGroup}
                            handleUpdateGroup={this.handleUpdateGroup} 
                            handlerShowModal={this.handleShow}/>
                    </tr>
                </thead>
                <tbody>
                    <CreateBodyElement
                        groupsName={this.state.groupsName}
                        listAdmin={this.groupsAdministrator}
                        listOtherGroup={this.listOtherGroup}/>                    
                </tbody>
            </Table>
            <ModalWindowAddNewGroup
                show={this.state.modalWindowAddShow}
                onHide={this.handleClose}
                listelement={this.props.mainInformation.administrator.elements}
                handleAddNewGroup={this.handleAddNewGroup} />
        </div>;
    }
}

CreateTable.propTypes = {
    socketIo: PropTypes.object.isRequired,
    mainInformation: PropTypes.object.isRequired,
    accessRights: PropTypes.object.isRequired
};

ReactDOM.render(<CreateTable 
    mainInformation={receivedFromServerMain} 
    accessRights={receivedFromServerAccess}
    socketIo={socket} />, document.getElementById("field_information"));

