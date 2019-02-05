/**
 * Модуль формирующий основную таблицу на странице
 * 
 * Версия 0.1, дата релиза 31.01.2019
 */

'use strict';

import React from 'react'
import ReactDOM from 'react-dom'
import { Button, Table } from 'react-bootstrap'
import PropTypes from 'prop-types'

import { helpers } from './common_helpers/helpers'
import { randomInteger } from './common_helpers/getRandomInt'
import ModalWindowAddNewGroup from './setting_groups_page/modalWindowAddNewGroup.jsx'

//перечисление типов действий доступных для администратора
class CreateListCategory extends React.Component {
    render() {
        let itemName = (typeof this.props.list.name === 'undefined') ? ' ' : <strong>{this.props.list.name}</strong>
        let liNoMarker = { 'listStyleType': 'none' }

        let isMenuItem = this.props.parameters.typeItem === 'menu_items'
        let moreThanTree = this.props.parameters.countSend === 3

        let createCategoryValue = <CreateCategoryValue
            list={this.props.list}
            parameters={this.props.parameters}
            key={`${this.props.parameters.group}_ul_key_${randomInteger(1, 1000) + this.props.parameters.uniqID}`} />

        if (this.props.parameters.group === 'administrator') {
            if (this.props.parameters.first) {
                return (
                    <ul className="text-left">
                        {itemName}
                        <ul style={liNoMarker}>
                            {createCategoryValue}
                        </ul>
                    </ul>)
            }

            if (isMenuItem || moreThanTree) {
                return (
                    <div>
                        {itemName}
                        <ul style={liNoMarker}>
                            {createCategoryValue}
                        </ul>
                    </div>)
            }

            return (
                <div>
                    {itemName}
                    {createCategoryValue}
                </div>)
        }

        if ((this.props.parameters.first) || isMenuItem || moreThanTree) {
            return (
                <div>
                    &nbsp;
                    {createCategoryValue}
                </div>)
        }

        return createCategoryValue
    }
}

CreateListCategory.propTypes = {
    list: PropTypes.object.isRequired,
    parameters: PropTypes.object.isRequired
}

//перечисление значений 
class CreateCategoryValue extends React.Component {
    render() {
        let arrItems = []
        let parameters = {
            'uniqID': this.props.parameters.uniqID + 1,
            'group': this.props.parameters.group,
            'typeItem': this.props.parameters.typeItem,
            'first': false
        }

        for (let item in this.props.list) {
            if (item === 'name') continue
            if (typeof this.props.list[item].status === 'undefined') {
                parameters.countSend = this.props.parameters.countSend + 1

                arrItems.push(
                    <CreateListCategory
                        list={this.props.list[item]}
                        parameters={parameters}
                        key={`${this.props.parameters.group}_value_${item}_${randomInteger(1, 1000) + parameters.uniqID}`} />)

                continue
            }

            let keyID = `sub_menu_${item}_${randomInteger(1, 1000) + parameters.uniqID}`
            let isDisabled, description = ''
            if (this.props.parameters.group === 'administrator') {
                isDisabled = 'disabled'
                description = this.props.list[item].description
            }

            arrItems.push(
                <div key={`${item}_${keyID}`}>
                    <input
                        type="checkbox"
                        disabled={isDisabled}
                        defaultChecked={this.props.list[item].status}
                        name="checkbox_administrator" />
                    {description}
                </div>)

            parameters.uniqID += parameters.uniqID
        }

        return arrItems
    }
}

CreateCategoryValue.propTypes = {
    list: PropTypes.object.isRequired,
    parameters: PropTypes.object.isRequired
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

    render() {
        let disabledCreate = (this.props.access.create.status) ? '' : 'disabled';

        return (
            <>
                <Button
                    variant="outline-primary"
                    size="sm"
                    onClick={this.handleShow.bind(this)}
                    disabled={disabledCreate} >
                    добавить
                </Button>

                <ModalWindowAddNewGroup
                    show={this.state.modalShow}
                    onHide={this.handleClose.bind(this)}
                    listelement={this.props.groupListElement} />
            </>
        )
    }
}

ButtonAddGroup.propTypes = {
    access: PropTypes.object.isRequired,
    groupListElement: PropTypes.object.isRequired
}

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
        )
    }
}

ButtonEdit.propTypes = { disabledEdit: PropTypes.string.isRequired }

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
        )
    }
}

ButtonDelete.propTypes = { disabledDelete: PropTypes.string.isRequired }

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
        let butAddGroup = <ButtonAddGroup
            access={this.props.accessRights}
            groupListElement={this.props.info.administrator.elements} />

        let arrGroup = this.props.groupsName.map(group => {
            if (group.toLowerCase() !== 'administrator') {
                bD = <ButtonDelete disabledDelete={disabledDelete} />
                bS = <ButtonEdit disabledEdit={disabledEdit} />
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

EnumGroupName.propTypes = {
    groupsName: PropTypes.arrayOf(PropTypes.string).isRequired,
    info: PropTypes.object.isRequired,
    accessRights: PropTypes.object.isRequired
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

ShowDateCreateGroup.propTypes = {
    groupsName: PropTypes.arrayOf(PropTypes.string).isRequired,
    info: PropTypes.object.isRequired,
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
                        <CreateListCategory
                            list={list[group].elements[item]}
                            parameters={listCategoryParameters}
                            key={`${group}_value_${item}_${randomInteger(1, 1000) + uniqID}`} />
                    </td>)
            })

            let keyID = `row_${item}_${randomInteger(1, 1000) + uniqID}`

            arrBody.push(
                <tr key={`${item}_${keyID}`}>
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
                            <ShowDateCreateGroup
                                groupsName={groupsName}
                                info={this.props.mainInformation} />
                        </tr>
                        <tr>
                            <EnumGroupName
                                groupsName={groupsName}
                                info={this.props.mainInformation}
                                accessRights={this.props.accessRights} />
                        </tr>
                    </thead>
                    <tbody>{arrBody}</tbody>
                </Table>
            </div>
        );
    }
}

CreateTable.propTypes = {
    mainInformation: PropTypes.object.isRequired,
    accessRights: PropTypes.object.isRequired
}

ReactDOM.render(<CreateTable
    mainInformation={receivedFromServerMain}
    accessRights={receivedFromServerAccess} />,
    document.getElementById('field_information'));

