/**
 * Модуль формирования модального окна добавления нового пользователя
 * 
 * Версия 0.1, дата релиза 31.01.2019
 */

import React from 'react'
import { Button, Modal, Table } from 'react-bootstrap'
import PropTypes from 'prop-types'

import { randomInteger } from '../common_helpers/getRandomInt'

//список доступных действий
class CreateListCategory extends React.Component {
    render() {
        let itemName = (typeof this.props.listelement.name === 'undefined') ? ' ' : <strong>{this.props.listelement.name}</strong>
        let liNoMarker = { 'listStyleType': 'none' }

        let isMenuItem = this.props.itemName === 'menu_items'
        let moreThanTree = this.props.countSend === 3

        let createCategoryValue =
            <CreateCategoryValue
                listelement={this.props.listelement}
                itemName={this.props.itemName}
                countSend={this.props.countSend}
                isListName={this.props.isListName}
                key={randomInteger(1, 1000)} />

        if (!this.props.isListName) {
            if (isMenuItem || this.props.isFirstItem || moreThanTree) {
                return (
                    <div>
                        &nbsp;
                        {createCategoryValue}
                    </div>
                )
            }

            return createCategoryValue
        }

        if (this.props.countSend === 1) {
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
}

CreateListCategory.propTypes = {
    listelement: PropTypes.object.isRequired,
    itemName: PropTypes.string.isRequired,
    countSend: PropTypes.number.isRequired,
    isListName: PropTypes.bool.isRequired
}

CreateListCategory.defaultProps = {
    isFirstItem: true
}

//создание элементов для выбора действий
class CreateCategoryValue extends React.Component {
    render() {
        let arrItems = []

        for (let item in this.props.listelement) {
            if (item === 'name') continue
            if (typeof this.props.listelement[item].status === 'undefined') {

                arrItems.push(
                    <CreateListCategory
                        listelement={this.props.listelement[item]}
                        itemName={this.props.itemName}
                        countSend={this.props.countSend + 1}
                        isListName={this.props.isListName}
                        isFirstItem={false}
                        key={`${item}_${randomInteger(1, 1000)}`} />)

                continue
            }

            let keyID = `sub_menu_${item}_${randomInteger(1, 1000)}`

            arrItems.push(
                <div key={keyID}>
                    {(this.props.isListName) ? this.props.listelement[item].description :
                        <input
                            name={item}
                            type="checkbox"
                            key={`check_box_${keyID}`} />}
                </div>)
        }

        return arrItems
    }
}

CreateCategoryValue.propTypes = {
    listelement: PropTypes.object.isRequired,
    itemName: PropTypes.string.isRequired,
    countSend: PropTypes.number.isRequired,
    isListName: PropTypes.bool.isRequired
}

//создание списка доступных действий
class CreateTable extends React.Component {
    handleChangeGroupName(event) {
        this.props.onUserInput(event.target.value)
    }

    render() {
        let num = 0
        let tableBody = []
        for (let item in this.props.listelement) {
            num++
            let arrTD = []

            for (let i = 1; i <= 2; i++) {
                arrTD.push(
                    <td
                        className={(i % 2) ? '' : 'text-center'}
                        key={`colum_${item}_${randomInteger(1, 1000) + num}`}>
                        <CreateListCategory
                            listelement={this.props.listelement[item]}
                            itemName={item}
                            countSend={1}
                            isListName={(i % 2) ? true : false}
                            key={`colum_${i}_${randomInteger(1, 1000) + i}`} />
                    </td>)
            }

            tableBody.push(
                <tr key={`line_${item}_${randomInteger(1, 1000) + num}`}>
                    {arrTD}
                </tr>)
        }

        return (
            <Table striped hover>
                <thead>
                    <tr key="header_line">
                        <th></th>
                        <th className="text-right">
                            <input
                                className="has-success"
                                id="new_group_name"
                                placeholder="название группы"
                                defaultValue={this.props.groupName}
                                onChange={this.handleChangeGroupName.bind(this)} />
                        </th>
                    </tr>
                </thead>
                <tbody>{tableBody}</tbody>
            </Table>
        )
    }
}

CreateTable.propTypes = {
    listelement: PropTypes.object.isRequired,
    groupName: PropTypes.string
}

class ModalWindowAddNewGroup extends React.Component {
    constructor() {
        super(...arguments)

        this.state = {
            groupName: '',
            groupNameValide: false
        }
    }

    handleUserInput(newGroup) {
        console.log(`new group name = ${newGroup}`)
        console.log(newGroup.length)

        if (newGroup.length > 4) {
            this.setState({
                groupName: newGroup,
                groupNameValide: true
            })
        }
    }

    handleClose() {
        this.props.onHide()
    }

    handleSave() {
        if (this.state.groupNameValide) {
            console.log('GROUP VALIDE')

            this.handleClose()
        } else {
            console.log('WARNING: GROUP INVALIDE!!!!')
        }
    }

    render() {
        return (
            <Modal
                {...this.props}
                size="lg"
                aria-labelledby="contained-modal-title-vcenter"
                centered
            >
                <Modal.Header closeButton>
                    <Modal.Title id="contained-modal-title-vcenter">
                        Добавить группу
                    </Modal.Title>
                </Modal.Header>
                <Modal.Body>

                    <CreateTable
                        listelement={this.props.listelement}
                        groupName={this.state.groupName}
                        onUserInput={this.handleUserInput.bind(this)} />

                </Modal.Body>
                <Modal.Footer>
                    <Button variant="outline-secondary" size="sm" onClick={this.handleClose.bind(this)}>
                        Закрыть
                    </Button>
                    <Button variant="outline-primary" size="sm" onClick={this.handleSave.bind(this)}>
                        Сохранить
                    </Button>
                </Modal.Footer>
            </Modal>
        );
    }
}

export default ModalWindowAddNewGroup 
