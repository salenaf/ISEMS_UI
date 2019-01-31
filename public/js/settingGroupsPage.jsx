/**
 * Модуль формирующий основную таблицу на странице
 * 
 * Версия 0.1, дата релиза 31.01.2019
 */

'use strict';

import React from 'react'
//import Button from 'react-bootstrap/Button'
import ReactDOM from 'react-dom'
import { Button, Table } from 'react-bootstrap'

import { helpers } from './common_helpers/helpers'
import { randomInteger } from './common_helpers/getRandomInt'
import ModalWindowAddNewGroup from './setting_groups_page/modalWindowAddNewGroup.jsx'

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

//перечисление типов действий доступных для администратора
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

//перечисление значений 
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

//кнопка 'добавить новую группу'
class ButtonAddGroup extends React.Component {
    constructor(props) {
        super(props)

        this.handleShow = this.handleShow.bind(this)
        this.handleClose = this.handleClose.bind(this)

        this.state = {
            modalShow: false,
        }
    }

    handleShow() {
        this.setState({ modalShow: true })
    }

    handleClose() {
        this.setState({ modalShow: false })
    }

    /*createModalWindow() {

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
                    
    }*/

    render() {
        let disabledCreate = (this.props.access.create.status) ? '' : 'disabled';

        return (
            <>
                <Button variant="outline-primary" size="sm" onClick={this.handleShow.bind(this)} disabled={disabledCreate} >
                    добавить
                </Button>

                <ModalWindowAddNewGroup show={this.state.modalShow} onHide={this.handleClose.bind(this)} />
            </>
        )
    }
}

//кнопка 'сохранить изменение параметров группы'
class ButtonSave extends React.Component {
    render() {
        return (
            <Button variant="outline-dark" size="sm" disabled={this.props.disabledEdit}>
                сохранить
            </Button>
        )
    }
}

//кнопка 'удалить группу'
class ButtonDelete extends React.Component {
    render() {
        return (
            <Button variant="outline-danger" size="sm" disabled={this.props.disabledEdit}>
                удалить
            </Button>
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

        let bD, bS 
        let textCenter = 'text-left'
        let butAddGroup = <ButtonAddGroup access={this.props.accessRights} />

        let arrGroup = this.props.groupsName.map(group => {
            if (group.toLowerCase() !== 'administrator') {
                bD = <ButtonDelete disabledDelete={disabledDelete} />
                bS = <ButtonSave disabledEdit={disabledEdit} />
                textCenter = "text-center"
                styleGroupName.paddingBottom = ''
                butAddGroup = ''
            }

            return (
                <th className={textCenter} style={styleGroupName} key={`group_name_${group}`}>
                    {group}&nbsp;
                    <div>{butAddGroup}&nbsp;{bS}&nbsp;{bD}</div>
                </th>)
        })

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
                textCenter = 'text-left'
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
                <h4 className="text-left text-uppercase">управление группами</h4>
                <Table striped hover>
                    <thead>
                        <tr>
                            <ShowDateCreateGroup groupsName={groupsName} info={this.props.mainInformation} />
                        </tr>
                        <tr>
                            <EnumGroupName groupsName={groupsName} info={this.props.mainInformation} accessRights={this.props.accessRights} />
                        </tr>
                    </thead>
                    <tbody>{arrBody}</tbody>
                </Table>
            </div>
        );
    }
}

ReactDOM.render(<CreateTable mainInformation={receivedFromServerMain} accessRights={receivedFromServerAccess} />,
    document.getElementById('field_information'));

(function () { })();
