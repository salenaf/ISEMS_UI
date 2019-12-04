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
import showNotifyMessage from "./common_helpers/showNotifyMessage";
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
                return (
                    <div>
                        {itemName}
                        <ul style={liNoMarker}>
                            {createCategoryValue}
                        </ul>
                    </div>);
            }

            return (
                <React.Fragment>
                    {itemName}
                    {createCategoryValue}
                </React.Fragment>);
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
                        name="checkbox_administrator" />
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

        this.props.changeGroup(data);
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
    changeGroup: PropTypes.func.isRequired,
    groupListElement: PropTypes.object.isRequired
};

//кнопка 'сохранить изменение параметров группы'
class ButtonEdit extends React.Component {
    render() {
        return (
            <Button
                variant="outline-dark"
                size="sm"
                disabled={this.props.disabledEdit}>
                сохранить
            </Button>
        );
    }
}

ButtonEdit.propTypes = { disabledEdit: PropTypes.string.isRequired };

//кнопка 'удалить группу'
class ButtonDelete extends React.Component {
    render() {
        return (
            <Button
                variant="outline-danger"
                size="sm"
                disabled={this.props.disabledDelete}>
                удалить
            </Button>
        );
    }
}

ButtonDelete.propTypes = { disabledDelete: PropTypes.string.isRequired };

//перечисление групп
class EnumGroupName extends React.Component {
    render() {
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
            groupListElement={this.props.list.administrator.elements} />;

        let arrGroup = this.props.groupsName.map(group => {
            if (group.toLowerCase() !== "administrator") {
                bDel = <ButtonDelete disabledDelete={disabledDelete} />;
                bEdit = <ButtonEdit disabledEdit={disabledEdit} />;
                textCenter = "text-center";
                styleGroupName.paddingBottom = "";
                butAddGroup = "";
            }

            return (
                <th className={textCenter} style={styleGroupName} key={`group_name_${group}`}>
                    {group}&nbsp;
                    <div>{butAddGroup}&nbsp;{bEdit}&nbsp;{bDel}</div>
                </th>);
        });

        return arrGroup;
    }
}

EnumGroupName.propTypes = {
    changeGroup: PropTypes.func,
    groupsName: PropTypes.arrayOf(PropTypes.string).isRequired,
    list: PropTypes.object.isRequired,
    accessRights: PropTypes.object.isRequired
};

//вывод даты создания группы
class ShowDateCreateGroup extends React.Component {
    render() {
        let dateCreate = this.props.groupsName.map(group => {
            let text = "";
            let textCenter = "text-center";

            if (group === "administrator") {
                text = "группа создана: ";
                textCenter = "text-left";
            }

            if (typeof this.props.list[group] === "undefined") return <th></th>;

            let [dateString,] = helpers.getDate(this.props.list[group].date_register).split(" ");
            let [year, month, day] = dateString.split("-");
            let dateCreate = `${day}.${month}.${year}`;

            return (
                <th
                    className={textCenter}
                    key={`date_create_${group}`}>
                    {`${text} ${dateCreate}`}
                </th>);
        });

        return dateCreate;
    }
}

ShowDateCreateGroup.propTypes = {
    groupsName: PropTypes.arrayOf(PropTypes.string).isRequired,
    list: PropTypes.object.isRequired,
};

class CreateBodyElement extends React.Component {
    createElement() {
        let { groupsName, list } = this.props;

        let arrTmp = [];
        for (let item in list.administrator.elements) {
            let arrTd = groupsName.map(group => {
                let listCategoryParameters = {
                    "group": group,
                    "countSend": 0,
                    "typeItem": item,
                    "first": true
                };

                return (
                    <td key={`td_${list[group].elements[item].id}`}>
                        <CreateListCategory
                            list={list[group].elements[item]}
                            parameters={listCategoryParameters}
                            key={list[group].elements[item].id} />
                    </td>);
            });

            arrTmp.push(
                <tr key={`tr_${list.administrator.elements[item].id}`}>
                    {arrTd}
                </tr>);
        }

        return arrTmp;
    }

    render() {
        let arrBody = this.createElement.call(this);

        return arrBody;
    }
}

CreateBodyElement.propTypes = {
    groupsName: PropTypes.arrayOf(PropTypes.string).isRequired,
    list: PropTypes.object.isRequired,
};

//создание основной таблицы
class CreateTable extends React.Component {
    constructor(props) {
        super(props);

        this.state = {
            groupsName: [],
            groupsInformation: {},
            oldGroupsName: [],
            oldGroupsInformation: {}
        };

        this.groupsName;
        //        this.groupsName = this.getGroupsName.call(this)
        this.changeGroup = this.changeGroup.bind(this);
        this.getGroupsName = this.getGroupsName.bind(this);
    }

    componentWillMount() {

        console.log("function componentWillMount");

        //        console.log(this.props.mainInformation)

        let stateCopy = Object.assign({}, this.state);
        stateCopy.groupsInformation = Object.assign(stateCopy.groupsInformation, this.props.mainInformation);
        this.setState(stateCopy);

        this.getGroupsName();

        /**  
         * 
         * ТЕПЕРЬ ИЗ СОСТОЯНИЯ groupsInformation МОЖНО БРАТЬ ВСЕ ДАННЫЕ В МЕСТО this.props.mainInformation
         * 
         */

        console.log("---- В состоянии храним ВСЮ информацию о группах ----");
        console.log(this.state);
    }

    getGroupsName() {
        let groups = Object.keys(this.props.mainInformation);
        groups.sort();

        console.log("function getGroupName");
        console.log(groups);

        let newGroups = groups.filter(item => item !== "administrator");
        let finalList = ["administrator"].concat(newGroups);

        let stateCopy = Object.assign({}, this.state);
        stateCopy.groupsName = Object.assign(stateCopy.groupsName, finalList);
        this.setState(stateCopy);

        this.groupsName = finalList;
    }

    showAlerts() {
        return <Alert variant='danger'>Message</Alert>;
    }

    changeGroup(data) {

        console.log("*-*-*-*-*-*-*-*-*-*-");
        console.log(data);

        let stateCopy = Object.assign({}, this.state);
        stateCopy.oldGroupsName = Object.assign(stateCopy.oldGroupsName, stateCopy.groupsName);
        stateCopy.oldGroupsInformation = Object.assign(stateCopy.oldGroupsInformation, stateCopy.groupsInformation);

        let newGroups = stateCopy.groupsName.filter(item => item !== "administrator").concat(data.groupName);
        newGroups.sort();
        stateCopy.groupsName = ["administrator"].concat(newGroups);

        console.log(stateCopy.groupsInformation.administrator);

        let newInfo = {};
        newInfo[data.groupName] = {};
        newInfo = Object.assign(newInfo[data.groupName], stateCopy.groupsInformation.administrator);

        /*
        
        НЕДОДЕЛАЛ
        необходимо пройтись по объекту, найти объект со свойством state,
        поичкать в альтернативном объекте 'data' совпадающий id и изменить 
        state на значение в объекте data
        
        let changeStatus = listElement => {
            for (let key in listElement) {
                if ((typeof listElement[key] === 'string')) continue
                if ('status' in listElement[key]) {


                    obj[listElement[key].id] = false
                    continue
                }

                changeStatus(listElement[key])
            }
        }

        changeStatus(newInfo)*/

        console.log(newInfo);
    }

    render() {
        socket.on("notify information", data => {

            console.log("resived MSG ---");
            console.log(data);

            let notify = JSON.parse(data.notify);

            if (notify.type === "success") {
                console.log("ADD GROUP SUCCESS!!!!");
            } else {
                console.log("ADD GROUP ___FAILURE___!!!!");
            }

            showNotifyMessage(data);
        });

        return <div>
            <h4 className="text-left text-uppercase">управление группами</h4>
            <Table striped hover>
                <thead>
                    <tr>
                        <ShowDateCreateGroup
                            groupsName={this.state.groupsName}
                            /*list={this.props.mainInformation}*/
                            list={this.state.groupsInformation} />
                    </tr>
                    <tr>
                        <EnumGroupName
                            changeGroup={this.changeGroup}
                            groupsName={this.state.groupsName}
                            list={this.state.groupsInformation}
                            accessRights={this.props.accessRights} />
                    </tr>
                </thead>
                <tbody>
                    <CreateBodyElement
                        /*groupsName={this.state.listGroups}*/
                        groupsName={this.state.groupsName}
                        list={this.state.groupsInformation} />
                </tbody>
            </Table>
        </div>;
    }
}

CreateTable.propTypes = {
    mainInformation: PropTypes.object.isRequired,
    accessRights: PropTypes.object.isRequired
};

ReactDOM.render(<CreateTable
    mainInformation={receivedFromServerMain}
    accessRights={receivedFromServerAccess} />,
document.getElementById("field_information"));

