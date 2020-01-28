import React from "react";
import { Button, Modal } from "react-bootstrap";
import PropTypes from "prop-types";

export default class ModalWindowOrganizationOrSource extends React.Component {
    constructor(props){
        super(props);

        console.log(props);

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
                        <h5>Редактировать источник №{this.props.settings.id}</h5>
                    </Modal.Title>
                </Modal.Header>
                <Modal.Body>... type: {this.props.settings.typeElem}</Modal.Body>
            </Modal>
        );
    }
}

ModalWindowOrganizationOrSource.propTypes = {
    show: PropTypes.bool,
    onHide: PropTypes.func,
    settings: PropTypes.object,
};