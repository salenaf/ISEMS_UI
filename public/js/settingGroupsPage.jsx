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
class CreateListCategory extends React.Component {
    render() {
        let itemName = (typeof this.props.list.name === "undefined") ? " " : <strong>{this.props.list.name}</strong>;
        let liNoMarker = { "listStyleType": "none" };

        let isMenuItem = this.props.parameters.typeItem === "menu_items";
        let moreThanTree = this.props.parameters.countSend === 3;

        let createCategoryValue = <CreateCategoryValue
            list={this.props.list}
            parameters={this.props.parameters} />;

        if (this.props.parameters.group === "administrator") {
            if (this.props.parameters.first) {
                return (
                    <ul className="text-left">
                        {itemName}
                        <ul style={liNoMarker}>
                            {createCategoryValue}
                        </ul>
                    </ul>);
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

CreateListCategory.propTypes = {
    list: PropTypes.object.isRequired,
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
                    <CreateListCategory
                        list={this.props.list[item]}
                        parameters={parameters}
                        key={`return_${this.props.list[item].id}`} />);

                continue;
            }

            let isDisabled, description = "";
            if (this.props.parameters.group === "administrator") {
                isDisabled = "disabled";
                description = this.props.list[item].description;
            }

            arrItems.push(
                <div key={`div_${this.props.list[item].id}`}>
                    <input
                        type="checkbox"
                        disabled={isDisabled}
                        defaultChecked={this.props.list[item].status}
                        name="checkbox_administrator" />&nbsp;
                    {description}
                </div>);
        }

        return arrItems;
    }
}

CreateCategoryValue.propTypes = {
    list: PropTypes.object.isRequired,
    parameters: PropTypes.object.isRequired
};

//кнопка 'добавить' новую группу
class ButtonAddGroup extends React.Component {
    constructor(props) {
        super(props);

        this.handleShow = this.handleShow.bind(this);
        this.handleClose = this.handleClose.bind(this);
        this.handleAddNewGroup = this.handleAddNewGroup.bind(this);

        this.state = {
            modalShow: false
        };
    }

    handleShow() {
        this.setState({ modalShow: true });
    }

    handleClose() {
        this.setState({ modalShow: false });
    }

    handleAddNewGroup(data) {
        socket.emit("add new group", {
            actionType: "create",
            arguments: data
        });

        //this.props.changeGroup(data);
    }

    render() {
        let disabledCreate = (this.props.access.create.status) ? "" : "disabled";

        return (<>
            <Button
                variant="outline-primary"
                size="sm"
                onClick={this.handleShow.bind(this)}
                disabled={disabledCreate} >
                добавить
            </Button>

            <ModalWindowAddNewGroup
                show={this.state.modalShow}
                onHide={this.handleClose}
                listelement={this.props.groupListElement}
                handleAddNewGroup={this.handleAddNewGroup} />
        </>);
    }
}

ButtonAddGroup.propTypes = {
    access: PropTypes.object.isRequired,
    //changeGroup: PropTypes.func.isRequired,
    groupListElement: PropTypes.object.isRequired
};

//кнопка 'сохранить изменение параметров группы'
class ButtonEdit extends React.Component {
    render() {
        return <Button
            variant="outline-dark"
            size="sm"
            disabled={this.props.disabledEdit}>
                сохранить
        </Button>;
    }
}

ButtonEdit.propTypes = { disabledEdit: PropTypes.string.isRequired };

//кнопка 'удалить группу'
class ButtonDelete extends React.Component {
    render() {
        return <Button
            variant="outline-danger"
            size="sm"
            disabled={this.props.disabledDelete}>
                удалить
        </Button>;
    }
}

ButtonDelete.propTypes = { disabledDelete: PropTypes.string.isRequired };

//перечисление групп
class EnumGroupName extends React.Component {
    render() {

        console.log("render EnumGroupName");

        let styleGroupName = {
            "paddingBottom": "13px"
        };

        let disabledEdit = (!this.props.accessRights.edit.status) ? "disabled" : "";
        let disabledDelete = (!this.props.accessRights.delete.status) ? "disabled" : "";

        let bEdit, bDel;
        let textCenter = "text-left";
        let butAddGroup = <ButtonAddGroup
            changeGroup={this.props.changeGroup}
            access={this.props.accessRights}
            groupListElement={this.props.listAdmin.elements} />;

        let arrGroup = this.props.groupsName.map(group => {
            if (group.groupName.toLowerCase() !== "administrator") {
                bDel = <ButtonDelete disabledDelete={disabledDelete} />;
                bEdit = <ButtonEdit disabledEdit={disabledEdit} />;
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
    //changeGroup: PropTypes.func,
    groupsName: PropTypes.arrayOf(PropTypes.object).isRequired,
    listAdmin: PropTypes.object.isRequired,
    accessRights: PropTypes.object.isRequired
};

//вывод даты создания группы
class ShowDateCreateGroup extends React.Component {
    render() {

        console.log("render ShowDateCreateGroup");

        let dateCreate = this.props.groupsName.map(group => {
            let text = "";
            let textCenter = "text-center";

            if (group.groupName === "administrator") {
                text = "группа создана: ";
                textCenter = "text-left";
            }

            //            if (typeof this.props.list[group] === "undefined") return <th></th>;
            //let [dateString,] = helpers.getDate(this.props.list[group].date_register).split(" ");
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
    groupsName: PropTypes.arrayOf(PropTypes.object).isRequired,
    //list: PropTypes.object.isRequired,
};

class CreateBodyElement extends React.Component {
    createElement() {
        let { groupsName, listAdmin, list } = this.props;

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
                        <CreateListCategory
                            list={listAdmin.elements[item]}
                            parameters={listCategoryParameters}
                            key={listAdmin.elements[item].id} />
                    </td>;    
                }

                return <td key={`td_${group.groupName}_${list[group.groupName].elements[item].id}`}>
                    <CreateListCategory
                        list={list[group.groupName].elements[item]}
                        parameters={listCategoryParameters}
                        key={list[group.groupName].elements[item].id} />
                </td>;
            });

            arrTmp.push(<tr key={`tr_${listAdmin.elements[item].id}`}>{arrTd}</tr>);
        }

        return arrTmp;
    }

    render() {

        console.log("render CreateBodyElement");

        let arrBody = this.createElement.call(this);

        return arrBody;
    }
}

CreateBodyElement.propTypes = {
    groupsName: PropTypes.arrayOf(PropTypes.object).isRequired,
    listAdmin: PropTypes.object.isRequired,
    list: PropTypes.object.isRequired,
};

//создание основной таблицы
class CreateTable extends React.Component {
    constructor(props) {
        super(props);

        this.state = {
            groupsName: this.getGroupsName(),
        };

        this.changeListGroupsInformation = this.changeListGroupsInformation.bind(this);

        console.log(this.state);
        
        this.groupsAdministrator = this.props.mainInformation.administrator;        
        this.listOtherGroup = this.changeListGroupsInformation(this.props.mainInformation);

        //это потом нужно убрать
        delete this.props.mainInformation.administrator;

        //и это тоже, в дольнейшем использовать только this.listOtherGroup
        this.groupsInformation = this.props.mainInformation;

        //console.log(this.groupsInformation);

        this.addNewGroup = this.addNewGroup.bind(this);
        this.updateGroup = this.updateGroup.bind(this);   
        this.deleteGroup = this.deleteGroup.bind(this);

        this.addListeners();
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
        let stateCopy = Object.assign({}, this.state);
        stateCopy.groupsName.push(newGroupObj.group_name);

        this.groupsInformation[newGroupObj.group_name] = {
            "date_register": newGroupObj.date_register,
            "elements": newGroupObj[newGroupObj.group_name],
        };

        console.log(stateCopy);
        console.log(this.groupsInformation);

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
                dateRegister: this.props.mainInformation[item].date_register
            });
        }

        return list;
    }

    changeListGroupsInformation(listOtherGroup){
        let newListOtherGroup = {};

        let obj = {};
        let getElementObject = (groupName, listElement) => {
            for (let key in listElement) {
                if ((typeof listElement[key] === "string")) continue;
                if ("status" in listElement[key]) {
                    obj[groupName][listElement[key].id] = {
                        keyID: listElement[key].id,
                        status: listElement[key].status,
                    };

                    continue;
                }

                getElementObject(groupName, listElement[key]);
            }
        };

        for(let groupName in listOtherGroup){
            obj[groupName] = {};

            getElementObject(groupName, listOtherGroup[groupName].elements);
        }

        /**
 * Redis не хочет делать глубокое изменение состояния, говорит что привышен лимит
 * глубины вложенности. Думаю стоит изменить структуру обрабатываемого объекта
 * со структуры которой соответствует this.groupsAdministrator на структуру
 * подобную:
 * deg_group: {93d09ed8e24d78ddfa6e928261b810f1: {…}, 35149067b45b054be53c32f4bf276e83: {…}, edc74022d022fdb1022fb235968cd888: {…}, d7cab65943607950489124da18ae1826: {…}, 9f66751bed474f792b841340bb16a8ec: {…}, …}
    deddddd: {
        165d93a9d3abdb56495d1e7502dcea0a: { // ГДЕ ЭТОТ ХЕШ ДОЛЖЕН БЫТЬ ОДИНАКОВ У ВСЕХ ГРУПП И СООТВЕТСТВОВАТЬ ХЕШУ группы administrator (по нему будет осуществлятся поиск)
            keyID: "165d93a9d3abdb56495d1e7502dcea0a"
            status: false
        }
    }
 * 
 * после формирования подобного объекта надо переделать CreateListCategory для работы с ним
 */

        console.log(obj);

        return newListOtherGroup;
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
                            accessRights={this.props.accessRights} />
                    </tr>
                </thead>
                <tbody>
                    <CreateBodyElement
                        groupsName={this.state.groupsName}
                        listAdmin={this.groupsAdministrator}
                        list={this.groupsInformation} />                    
                </tbody>
            </Table>
        </div>;
    }
}

/*
<CreateBodyElement
                        groupsName={this.state.groupsName}
                        list={this.groupsInformation} />
*/

CreateTable.propTypes = {
    socketIo: PropTypes.object.isRequired,
    mainInformation: PropTypes.object.isRequired,
    accessRights: PropTypes.object.isRequired
};

ReactDOM.render(<CreateTable 
    mainInformation={receivedFromServerMain} 
    accessRights={receivedFromServerAccess}
    socketIo={socket} />, document.getElementById("field_information"));

