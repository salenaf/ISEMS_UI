/**
 * Модуль формирования модального окна добавления нового пользователя
 * 
 * Версия 0.11, дата релиза 11.02.2019
 */

import React from 'react'
import { Alert, Button, Modal, Table } from 'react-bootstrap'
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
                checkboxMarked={this.props.checkboxMarked}
                itemName={this.props.itemName}
                countSend={this.props.countSend}
                isListName={this.props.isListName}
                onChangeUserInput={this.props.onChangeUserInput} />

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
    checkboxMarked: PropTypes.object.isRequired,
    itemName: PropTypes.string.isRequired,
    countSend: PropTypes.number.isRequired,
    isListName: PropTypes.bool.isRequired,
    onChangeUserInput: PropTypes.func.isRequired
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
                        checkboxMarked={this.props.checkboxMarked}
                        itemName={this.props.itemName}
                        countSend={this.props.countSend + 1}
                        isListName={this.props.isListName}
                        onChangeUserInput={this.props.onChangeUserInput}
                        isFirstItem={false}
                        key={`return_${this.props.listelement[item].id}`} />)

                continue
            }

            arrItems.push(
                <div key={`div_${this.props.listelement[item].id}`}>
                    {(this.props.isListName) ? this.props.listelement[item].description :
                        <input
                            name={item}
                            type="checkbox"
                            id={this.props.listelement[item].id}
                            defaultChecked={this.props.checkboxMarked[this.props.listelement[item].id]}
                            onChange={this.props.onChangeUserInput} />}
                </div>)
        }

        return arrItems
    }
}

CreateCategoryValue.propTypes = {
    listelement: PropTypes.object.isRequired,
    checkboxMarked: PropTypes.object.isRequired,
    itemName: PropTypes.string.isRequired,
    countSend: PropTypes.number.isRequired,
    isListName: PropTypes.bool.isRequired,
    onChangeUserInput: PropTypes.func.isRequired
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
                        className={(i === 2) ? 'text-center' : ''} >

                        <CreateListCategory
                            listelement={this.props.listelement[item]}
                            checkboxMarked={this.props.checkboxMarked}
                            itemName={item}
                            countSend={1}
                            isListName={(i % 2) ? true : false}
                            onChangeUserInput={this.props.onChangeUserInput}
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
    checkboxMarked: PropTypes.object.isRequired,
    onUserInput: PropTypes.func.isRequired,
    onChangeUserInput: PropTypes.func.isRequired,
    groupName: PropTypes.string.isRequired,
    classGroupNameValide: PropTypes.string
}

class AlertMessage extends React.Component {
    render() {
        return (<>
            <Alert dismissible variant="danger" show={this.props.show} onClose={this.props.onCloseHandle}>
                <Alert.Heading>Ошибка при сохранении!</Alert.Heading>
                <p>Вероятно вы забыли написать название группы или не выбрали ни одного из элементов перечисленных выше.</p>
            </Alert>
        </>)
    }
}

AlertMessage.propTypes = {
    show: PropTypes.bool.isRequired,
    onCloseHandle: PropTypes.func.isRequired
}

class ModalWindowAddNewGroup extends React.Component {
    constructor() {
        super(...arguments)

        this.state = {
            showAlert: false,
            groupName: '',
            groupNameValide: false,
            classGroupName: 'form-control',
            checkboxMarked: {}
        }

        this.handleSave = this.handleSave.bind(this)
        this.handleClose = this.handleClose.bind(this)
        this.clearElements = this.clearElements.bind(this)
        this.onCloseHandle = this.onCloseHandle.bind(this)
        this.handleUserInput = this.handleUserInput.bind(this)
        this.setCheckboxMarked = this.setCheckboxMarked.bind(this)
        this.handleAddNewGroup = this.props.handleAddNewGroup.bind(this)
        this.changeCheckboxMarked = this.changeCheckboxMarked.bind(this)
    }

    componentWillMount() {
        this.setCheckboxMarked()
    }

    componentDidUpdate(prevProp) {
        if (!prevProp.show) {
            this.clearElements()
        }
    }

    clearElements() {
        let stateCopy = Object.assign({}, this.state)

        stateCopy.showAlert = false
        stateCopy.groupName = ''
        stateCopy.groupNameValide = false
        stateCopy.classGroupName = 'form-control'

        for (let id in stateCopy.checkboxMarked) {
            stateCopy.checkboxMarked[id] = false
        }

        this.setState(stateCopy)
    }

    onCloseHandle() {
        this.setState({ showAlert: false })
    }

    setCheckboxMarked() {
        let obj = {}
        let getElementObject = listElement => {
            for (let key in listElement) {
                if ((typeof listElement[key] === 'string')) continue
                if ('status' in listElement[key]) {
                    obj[listElement[key].id] = false
                    continue
                }

                getElementObject(listElement[key])
            }
        }

        getElementObject(this.props.listelement)

        this.setState({ checkboxMarked: obj })
    }

    changeCheckboxMarked(event) {
        let id = event.currentTarget.id

        let stateCopy = Object.assign({}, this.state)
        stateCopy.checkboxMarked[id] = !this.state.checkboxMarked[id]
        this.setState({ stateCopy })
    }

    handleUserInput(groupName) {
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
        this.props.onHide()

        this.clearElements()
    }

    handleSave() {
        let listActions = Object.assign({}, this.state.checkboxMarked)

        let isChecked = Object.keys(listActions).some(item => {
            return listActions[item]
        })

        if (this.state.groupNameValide && isChecked) {

            this.handleAddNewGroup({
                groupName: this.state.groupName,
                listPossibleActions: listActions
            })

            this.handleClose()
        } else {
            this.setState({ showAlert: true })
        }
    }

    render() {
        return (
            <Modal
                show={this.props.show}
                onHide={this.props.onHide}
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
                        checkboxMarked={this.state.checkboxMarked}
                        groupName={this.state.groupName}
                        classGroupNameValide={this.state.classGroupName}
                        onChangeUserInput={this.changeCheckboxMarked}
                        onUserInput={this.handleUserInput} />

                </Modal.Body>
                <Modal.Footer>
                    <AlertMessage show={this.state.showAlert} onCloseHandle={this.onCloseHandle} />
                    <Button variant="outline-secondary" size="sm" onClick={this.handleClose}>
                        Закрыть
                    </Button>
                    <Button variant="outline-primary" size="sm" onClick={this.handleSave}>
                        Сохранить
                    </Button>
                </Modal.Footer>
            </Modal>
        );
    }
}

export default ModalWindowAddNewGroup 
