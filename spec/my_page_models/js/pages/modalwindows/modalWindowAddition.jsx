import React from "react";
import { Button, Modal } from "react-bootstrap";
import PropTypes from "prop-types";

export default class ModalWindowAddition extends React.Component {
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
                        <h5>Добавить</h5>
                    </Modal.Title>
                </Modal.Header>
                <Modal.Body>...</Modal.Body>
            </Modal>
        );
    }
}

ModalWindowAddition.propTypes = {
    settings: PropTypes.object,
    show: PropTypes.bool,
    onHide: PropTypes.func,
};