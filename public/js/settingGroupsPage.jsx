'use strict';

import React from 'react'
import ReactDOM from 'react-dom'

import { randomInteger } from './common_helpers/getRandomInt'

//создание списка разделов сайта
class CreateListCategory extends React.Component {
    constructor(props) {
        super(props)
    }

    render() {
        const list = this.props.list

        let itemName = (typeof list.name !== 'undefined') ? <strong>{list.name}</strong> : ''
        let liNoMarker = { 'listStyleType': 'none' }

        if (this.props.first) {
            return (
                <ul className="text-left">
                    {itemName}
                    <ul style={liNoMarker}>
                        <CreateCategoryItems list={list} countSend={this.props.countSend} key={randomInteger(1, 1000)} />
                    </ul>
                </ul>)
        }

        if (this.props.countSend === 3) {
            return (
                <div>
                    {itemName}
                    <ul style={liNoMarker}>
                        <CreateCategoryItems list={list} countSend={this.props.countSend} key={randomInteger(1, 1000)} />
                    </ul>
                </div>)
        }

        return (
            <div>
                {itemName}
                <CreateCategoryItems list={list} countSend={this.props.countSend} key={randomInteger(1, 1000)} />
            </div>)
    }
}

//перечисление типов действий доступных для каждого раздела
class CreateCategoryItems extends React.Component {
    constructor(props) {
        super(props)
    }

    render() {
        let arrItems = []
        let uniqID = this.props.uniqID
        let list = this.props.list

        let countSend = this.props.countSend

        for (let item in list) {
            if (item === 'name') continue
            if (typeof list[item].description === 'undefined') {
                arrItems.push(
                    <CreateListCategory countSend={countSend + 1} list={list[item]} first={false} key={randomInteger(1, 1000)} />)

                continue
            }

            let keyID = `sub_menu_${item}_${randomInteger(1, 1000) + uniqID}`

            arrItems.push(
                <li className="sub-menu" key={keyID}>
                    {list[item].description}
                </li>)

            uniqID++
        }

        return arrItems
    }
}

//кнопка добавления новой группы
class ButtonAddGroup extends React.Component {
    constructor(props) {
        super(props)
    }

    render() {
        let disabledCreate = (this.props.access.create.status) ? '' : 'disabled';

        return (
            <button type="button" className="btn btn-default btn-sm" id="buttonAddGroup" disabled={disabledCreate} >
                <span className="glyphicon glyphicon-plus"></span> добавить
            </button>
        )
    }
}

//кнопка сохранение параметров группы
class ButtonSave extends React.Component {
    constructor(props) {
        super(props)
    }

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
    constructor(props) {
        super(props)
    }

    render() {
        return (
            <button type="button" className="btn btn-default btn-sm" name="buttonDelGroup" disabled={this.props.disabledDelete}>
                <span className="glyphicon glyphicon-trash"></span>
            </button>
        )
    }
}

//список установленных значений
class CreateListValue extends React.Component {
    constructor(props) {
        super(props)
    }

    render() {
        let arrRows = []

        return arrRows
    }
}

//перечисление групп
class AddGroupName extends React.Component {
    constructor(props) {
        super(props)
    }

    render() {
        let styleGroupName = {
            'paddingBottom': '13px'
        }

        let disabledEdit = (!this.props.accessRights.edit.status) ? 'disabled' : '';
        let disabledDelete = (!this.props.accessRights.delete.status) ? 'disabled' : '';

        let arrGroup = [];
        let bD, bS = ''

        for (let group in this.props.info) {
            if (group.toLowerCase() !== 'administrator') {
                bD = <ButtonDelete disabledDelete={disabledDelete} />
                bS = <ButtonSave disabledEdit={disabledEdit} />
                styleGroupName.paddingBottom = ''
            }

            arrGroup.push(
                <th className="text-left" style={styleGroupName} key={group}>
                    {group}&nbsp;
                    {bD}&nbsp;
                    {bS}&nbsp;
                </th>)
        }

        //                        создана: {this.props.info[group].date_register}
        return arrGroup
    }
}

//создание основной таблицы
class CreateTable extends React.Component {
    constructor(props) {
        super(props);
        this.state = {}
    }

    render() {
        let divStyleWidth = {
            width: '35%'
        }

        let arrRows = []
        let list = this.props.mainInformation
        let uniqID = 0

        for (let item in list.administrator.elements) {
            let keyID = `row_${item}_${randomInteger(1, 1000) + uniqID}`

            arrRows.push(
                <tr key={keyID}>
                    <td>
                        <CreateListCategory countSend={0} list={list.administrator.elements[item]} first={true} key={uniqID} />
                    </td>
                    <CreateListValue list={list} />
                </tr>)

            uniqID++
        }

        return (
            <div>
                <table className="table table-striped table-hover table-sm">
                    <caption className="h4 text-uppercase">управление группами</caption>
                    <thead>
                        <tr>
                            <th className="text-right" style={divStyleWidth}>
                                <ButtonAddGroup access={this.props.accessRights} />
                            </th>
                            <AddGroupName info={this.props.mainInformation} accessRights={this.props.accessRights} />
                        </tr>
                    </thead>
                    <tbody>{arrRows}</tbody>
                </table>
            </div>
        );
    }
}

ReactDOM.render(<CreateTable mainInformation={receivedFromServerMain} accessRights={receivedFromServerAccess} />,
    document.getElementById('field_information'));

(function () { })();
