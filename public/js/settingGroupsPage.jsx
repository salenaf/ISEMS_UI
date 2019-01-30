'use strict';

import React from 'react'
import ReactDOM from 'react-dom'

import { helpers } from './common_helpers/helpers'
import { randomInteger } from './common_helpers/getRandomInt'

//создание списка разделов сайта
/*class CreateListCategory extends React.Component {
    render() {
        let itemName = (typeof this.props.parameters.list.name === 'undefined') ? ' ' : <strong>{this.props.parameters.list.name}</strong>
        let liNoMarker = { 'listStyleType': 'none' }

        if (this.props.parameters.first) {
            return (
                <ul className="text-left">
                    {itemName}
                    <ul style={liNoMarker}>
                        <CreateCategoryItems parameters={this.props.parameters} key={randomInteger(1, 1000)} />
                    </ul>
                </ul>)
        }

        if ((this.props.parameters.typeItem === 'menu_items') || (this.props.parameters.countSend === 3)) {
            return (
                <div>
                    {itemName}
                    <ul style={liNoMarker}>
                        <CreateCategoryItems parameters={this.props.parameters} key={randomInteger(1, 1000)} />
                    </ul>
                </div>)
        }

        return (
            <div>
                {itemName}
                <CreateCategoryItems parameters={this.props.parameters} key={randomInteger(1, 1000)} />
            </div>)
    }
}

//перечисление типов действий доступных для каждого раздела
class CreateCategoryItems extends React.Component {
    render() {
        let arrItems = []
        let parameters = {
            'typeItem': this.props.parameters.typeItem,
            'first': false
        }

        for (let item in this.props.parameters.list) {
            if (item === 'name') continue
            if (typeof this.props.parameters.list[item].description === 'undefined') {
                parameters.countSend = this.props.parameters.countSend + 1
                parameters.list = this.props.parameters.list[item]

                arrItems.push(
                    <CreateListCategory parameters={parameters} key={randomInteger(1, 1000)} />)

                continue
            }

            let keyID = `sub_menu_${item}_${randomInteger(1, 1000) + parameters.uniqID}`

            arrItems.push(
                <li className="sub-menu" key={keyID}>
                    {this.props.parameters.list[item].description}
                </li>)

            parameters.uniqID = this.props.parameters.uniqID + 1
        }

        return arrItems
    }
}*/

class CreateAdminCategory extends React.Component {
    render() {
        let itemName = (typeof this.props.list.name === 'undefined') ? ' ' : <strong>{this.props.list.name}</strong>
        let liNoMarker = { 'listStyleType': 'none' }

        let isMenuItem = this.props.parameters.typeItem === 'menu_items'
        let moreThanTree = this.props.parameters.countSend === 3

        if (this.props.parameters.group === 'administrator') {
            if (this.props.parameters.first) {
                return (
                    <ul className="text-left">
                        {itemName}
                        <ul style={liNoMarker}>
                            <CreateCategoryValue list={this.props.list} parameters={this.props.parameters} key={randomInteger(1, 1000)} />
                        </ul>
                    </ul>)
            }

            if (isMenuItem || moreThanTree) {
                return (
                    <div>
                        {itemName}
                        <ul style={liNoMarker}>
                            <CreateCategoryValue list={this.props.list} parameters={this.props.parameters} key={randomInteger(1, 1000)} />
                        </ul>
                    </div>)
            }

            return (
                <div>
                    {itemName}
                    <CreateCategoryValue list={this.props.list} parameters={this.props.parameters} key={randomInteger(1, 1000)} />
                </div>)
        }

        if ((this.props.parameters.first) || isMenuItem || moreThanTree) {
            return (
                <div>
                    &nbsp;
                <CreateCategoryValue list={this.props.list} parameters={this.props.parameters} key={randomInteger(1, 1000)} />
                </div>)
        }

        return <CreateCategoryValue list={this.props.list} parameters={this.props.parameters} key={randomInteger(1, 1000)} />
    }
}

//перечисление типов действий доступных для администратора
class CreateCategoryValue extends React.Component {
    render() {
        let arrItems = []
        let parameters = {
            'group': this.props.parameters.group,
            'typeItem': this.props.parameters.typeItem,
            'first': false
        }

        for (let item in this.props.list) {
            if (item === 'name') continue
            if (typeof this.props.list[item].status === 'undefined') {
                parameters.countSend = this.props.parameters.countSend + 1
                parameters.list = this.props.list[item]

                arrItems.push(
                    <CreateAdminCategory list={this.props.list[item]} parameters={parameters} key={randomInteger(1, 1000)} />)

                continue
            }

            let keyID = `sub_menu_${item}_${randomInteger(1, 1000) + parameters.uniqID}`
            let isDisabled, description = ''
            if (this.props.parameters.group === 'administrator') {
                isDisabled = 'disabled'
                description = this.props.list[item].description
            }

            arrItems.push(
                <div key={keyID}>
                    <input type="checkbox" disabled={isDisabled} defaultChecked={this.props.list[item].status} name="checkbox_administrator" />
                    {description}
                </div>)

            parameters.uniqID = this.props.parameters.uniqID + 1
        }

        return arrItems
    }
}

//вызов модального окна добавления новой группы
class OpenModalWindowAddNewGroup extends React.Component {
    render() {

        console.log('OPEN MODAL WINDOW ADD GROUP')

        return <div></div>
    }
}

//кнопка добавления новой группы
class ButtonAddGroup extends React.Component {

    openModalWindowAddNewGroup() {
        console.log('OPEN MODAL WINDOW ADD GROUP')

        return this.createModalWindow()
    }

    createModalWindow() {

        return (
            <div className="modal fade" tabindex="-1" role="dialog" aria-labelledby="myModalLabel" data-show="data">
                <div className="modal-dialog" role="document">
                    <div className="modal-content">
                        <div className="modal-header">
                            <button type="button" className="close" data-dismiss="modal" aria-label="Close"><span aria-hidden="true">&times;</span></button>
                            <h4 className="modal-title">Добавить группу</h4>
                        </div>
                        <div className="modal-body">
                            <div className="container-fluid">
                                <div className="row">
                                    <div className="col-md-12">

                                    </div>
                                </div>
                            </div>
                        </div>
                        <div className="modal-footer">
                            <button type="button" className="btn btn-default" data-dismiss="modal">Закрыть</button>
                            <button type="submit" className="btn btn-primary">Сохранить</button>
                        </div>
                    </div>
                </div>
            </div>
        )
    }

    render() {
        let disabledCreate = (this.props.access.create.status) ? '' : 'disabled';

        return (
            <button onClick={this.openModalWindowAddNewGroup.bind(this)} type="button" className="btn btn-default btn-sm" id="buttonAddGroup" disabled={disabledCreate} >
                <span className="glyphicon glyphicon-plus"></span> добавить
            </button>
        )
    }
}

//кнопка сохранение параметров группы
class ButtonSave extends React.Component {
    render() {
        return (
            <button type="button" className="btn btn-default btn-sm" name="buttonEditGroup" disabled={this.props.disabledEdit}>
                <span className="glyphicon glyphicon-floppy-saved"></span>
            </button>
        )
    }
}

//кнопка удаления группы
class ButtonDelete extends React.Component {
    render() {
        return (
            <button type="button" className="btn btn-default btn-sm" name="buttonDelGroup" disabled={this.props.disabledDelete}>
                <span className="glyphicon glyphicon-trash"></span>
            </button>
        )
    }
}

//перечисление групп
class EnumGroupName extends React.Component {
    render() {
        let styleGroupName = {
            'paddingBottom': '13px'
        }

        let disabledEdit = (!this.props.accessRights.edit.status) ? 'disabled' : '';
        let disabledDelete = (!this.props.accessRights.delete.status) ? 'disabled' : '';

        let bD, bS = ''
        let butAddGroup = <ButtonAddGroup access={this.props.accessRights} />

        let arrGroup = this.props.groupsName.map(group => {
            if (group.toLowerCase() !== 'administrator') {
                bD = <ButtonDelete disabledDelete={disabledDelete} />
                bS = <ButtonSave disabledEdit={disabledEdit} />
                styleGroupName.paddingBottom = ''
                butAddGroup = ''
            }

            return (
                <th className="text-left" style={styleGroupName} key={`group_name_${group}`}>
                    {group}&nbsp;
                    {butAddGroup}&nbsp;
                    {bD}&nbsp;
                    {bS}&nbsp;
                </th>)
        })

        //                        создана: {this.props.info[group].date_register}
        return arrGroup
    }
}

//вывод даты создания группы
class ShowDateCreateGroup extends React.Component {
    render() {
        let dateCreate = this.props.groupsName.map(group => {
            let text = ''
            let textCenter = 'text-center'
            if (group === 'administrator') {
                text = 'группа создана: '
                textCenter = ''
            }

            let [dateString,] = helpers.getDate(this.props.info[group].date_register).split(' ')
            let [year, month, day] = dateString.split('-')
            let dateCreate = `${day}.${month}.${year}`

            return (
                <th className={textCenter} key={`date_create_${group}`}>{`${text} ${dateCreate}`}</th>
            )
        })

        return dateCreate
    }
}

//создание основной таблицы
class CreateTable extends React.Component {
    constructor(props) {
        super(props);
        this.state = {}
    }

    render() {
        let list = this.props.mainInformation
        let uniqID = 0

        let groups = Object.keys(list)
        groups.sort()

        let newGroups = groups.filter(item => item !== 'administrator')
        let groupsName = ['administrator'].concat(newGroups)

        let arrBody = []
        for (let item in list.administrator.elements) {
            let arrTd = groupsName.map(group => {
                let listCategoryParameters = {
                    'group': group,
                    'countSend': 0,
                    'typeItem': item,
                    'first': true,
                    'uniqID': uniqID
                }

                return (
                    <td key={`${group}_${item}_${uniqID}`}>
                        <CreateAdminCategory list={list[group].elements[item]} parameters={listCategoryParameters} key={`value_${uniqID}`} />
                    </td>)
            })

            let keyID = `row_${item}_${randomInteger(1, 1000) + uniqID}`

            arrBody.push(
                <tr key={keyID}>
                    {arrTd}
                </tr>)

            uniqID++
        }

        return (
            <div>
                <table className="table table-striped table-hover table-sm">
                    <caption className="h4 text-uppercase">управление группами</caption>
                    <thead>
                        <tr>
                            <ShowDateCreateGroup groupsName={groupsName} info={this.props.mainInformation} />
                        </tr>
                        <tr>
                            <EnumGroupName groupsName={groupsName} info={this.props.mainInformation} accessRights={this.props.accessRights} />
                        </tr>
                    </thead>
                    <tbody>{arrBody}</tbody>
                </table>
            </div>
        );
    }
}

ReactDOM.render(<CreateTable mainInformation={receivedFromServerMain} accessRights={receivedFromServerAccess} />,
    document.getElementById('field_information'));

(function () { })();
