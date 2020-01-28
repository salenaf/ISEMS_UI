import React from "react";
import { Button, Form, Modal } from "react-bootstrap";
import PropTypes from "prop-types";

class CreateBodyOrganization extends React.Component {
    constructor(props){
        super(props);
    }

    createListFieldActivity(){
        let list = Object.keys(this.props.listFieldActivity);
        list.sort();

        let num = 1;
        return (
            <Form.Group>
                <Form.Label>Вид деятельности</Form.Label>
                <Form.Control as="select">
                    {list.map((item) => <option value={item} key={`list_field_activity_${num++}`}>{item}</option>)}
                </Form.Control>
            </Form.Group>
        );         
    }

    render(){
        return (
            <Form>
                <Form.Group>
                    <Form.Label>Название организации</Form.Label>
                    <Form.Control type="text" />
                </Form.Group>
                {this.createListFieldActivity.call(this)}
                <Form.Group>
                    <Form.Label>Юридический адрес</Form.Label>
                    <Form.Control as="textarea" rows="2" />
                </Form.Group>
            </Form>
        );
    }
}

CreateBodyOrganization.propTypes = {
    listFieldActivity: PropTypes.object.isRequired,
};

class CreateBodyDivision extends React.Component {
    constructor(props){
        super(props);
    }

    render(){
        return (
            <Form>
                <Form.Group>
                    <Form.Label>Название подразделения или филиала</Form.Label>
                    <Form.Control type="text" />
                </Form.Group>
                <Form.Group>
                    <Form.Label>Физический адрес</Form.Label>
                    <Form.Control as="textarea" rows="2" />
                </Form.Group>
                <Form.Group>
                    <Form.Label>Примечание</Form.Label>
                    <Form.Control as="textarea" rows="3" />
                </Form.Group>
            </Form>
        );
    }
}

CreateBodyDivision.propTypes = {

};

class CreateBodySource extends React.Component {
    constructor(props){
        super(props);
    }

    render(){
        return (
            <React.Fragment>
           Подразделение
            </React.Fragment>
        );
    }
}

CreateBodySource.propTypes = {

};

class CreateModalBody extends React.Component {
    constructor(props){
        super(props);
    }

    render(){
        switch(this.props.typeModalBody){
        case "organization":
            return <CreateBodyOrganization listFieldActivity={this.props.listFieldActivity} />;

        case "division":
            return <CreateBodyDivision />;

        case "source":
            return <CreateBodySource />;

        default: 
            return;
        }
    }
}

CreateModalBody.propTypes = {
    typeModalBody: PropTypes.string,
    listFieldActivity: PropTypes.object.isRequired,
};

export default class ModalWindowAddEntity extends React.Component {
    constructor(props){
        super(props);

        this.windowClose = this.windowClose.bind(this); 
    }

    windowClose(){
        this.props.onHide();
    }

    render(){
        return (
            <Modal
                size="lg"
                show={this.props.show} 
                onHide={this.windowClose}
                aria-labelledby="example-modal-sizes-title-lg"
            >
                <Modal.Header closeButton>
                    <Modal.Title id="example-modal-sizes-title-lg">
                        <h5>Добавить {this.props.settings.name}</h5>
                    </Modal.Title>
                </Modal.Header>
                <Modal.Body>
                    <CreateModalBody 
                        typeModalBody={this.props.settings.type}
                        listFieldActivity={this.props.settings.listFieldActivity} />
                </Modal.Body>
                <Modal.Footer>
                    <Button onClick={this.windowClose} variant="outline-secondary">закрыть</Button>
                    <Button variant="outline-primary">добавить</Button>
                </Modal.Footer>
            </Modal>
        );
    }
}

ModalWindowAddEntity.propTypes = {
    show: PropTypes.bool,
    onHide: PropTypes.func,
    settings: PropTypes.object,
};