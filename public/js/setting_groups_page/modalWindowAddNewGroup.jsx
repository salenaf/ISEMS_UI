/**
 * Модуль формирования модального окна добавления нового пользователя
 * 
 * Версия 0.11, дата релиза 11.02.2019
 */

import React from 'react'
import { Button, Modal, Table } from 'react-bootstrap'
import PropTypes from 'prop-types'

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
                isListName={this.props.isListName} />

        if (!this.props.isListName) {
            if (isMenuItem || this.props.isFirstItem || moreThanTree) {
                return <div>&nbsp;{createCategoryValue}</div>
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
            if (item === 'name' || item === 'id') continue
            if (typeof this.props.listelement[item].status === 'undefined') {

                arrItems.push(
                    <CreateListCategory
                        listelement={this.props.listelement[item]}
                        itemName={this.props.itemName}
                        countSend={this.props.countSend + 1}
                        isListName={this.props.isListName}
                        isFirstItem={false}
                        key={`return_${this.props.listelement[item].id}`} />)

                continue
            }

            arrItems.push(
                <div key={`div_${this.props.listelement[item].id}`}>
                    {(this.props.isListName) ? this.props.listelement[item].description :
                        <input
                            name={item}
                            type="checkbox" />}
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

    createTableBody() {
        let tableBody = []
        for (let item in this.props.listelement) {
            let arrTD = []

            for (let i = 1; i <= 2; i++) {
                arrTD.push(
                    <td
                        key={`td_${this.props.listelement[item].id}_${i}`}
                        className={(i % 2) ? '' : 'text-center'}>
                        <CreateListCategory
                            listelement={this.props.listelement[item]}
                            itemName={item}
                            countSend={1}
                            isListName={(i % 2) ? true : false}
                            key={`${this.props.listelement[item].id}_${i}`} />
                    </td>)
            }

            tableBody.push(
                <tr key={`tr_${this.props.listelement[item].id}`}>
                    {arrTD}
                </tr>)
        }

        return <tbody>{tableBody}</tbody>
    }

    render() {
        return (
            <Table striped hover>
                <thead>
                    <tr key="header_line">
                        <th></th>
                        <th className="text-right">
                            <input
                                className={this.props.classGroupNameValide}
                                id="new_group_name"
                                placeholder="новая группа"
                                defaultValue={this.props.groupName}
                                onChange={this.handleChangeGroupName.bind(this)} />
                        </th>
                    </tr>
                </thead>
                {this.createTableBody.call(this)}
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
            groupNameValide: false,
            classGroupName: 'form-control'
        }
    }

    handleUserInput(groupName) {
        console.log(`new group name = ${groupName}`)
        console.log(groupName.length)

        if (/\b^[a-zA-Z0-9]{4,}$\b/.test(groupName)) {
            this.setState({
                groupName: groupName,
                groupNameValide: true,
                classGroupName: 'form-control is-valid'
            })
        } else {
            this.setState({
                groupNameValide: false,
                classGroupName: 'form-control is-invalid'
            })
        }
    }

    handleClose() {

        console.log(11111)

        this.props.onHide()
        this.setState({
            groupName: '',
            groupNameValide: false,
            classGroupName: 'form-control'
        })

        console.log('CLOSE')
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
                        classGroupNameValide={this.state.classGroupName}
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
