"use strict";

import React from "react";
import { Button, Modal, Spinner } from "react-bootstrap";
import PropTypes from "prop-types";

export default class ModalWindowListTaskDownloadFiles extends React.Component {
    constructor(props){
        super(props);
    }

    render(){
        return (
            <Modal
                size="lg"
                show={this.props.show} 
                onHide={this.props.onHide}
                aria-labelledby="example-modal-sizes-title-lg" >
                <Modal.Header closeButton>
                    <Modal.Title id="example-modal-sizes-title-lg">
                        <h5>Загрузка файлов</h5>
                    </Modal.Title>
                </Modal.Header>
                <Modal.Body>
                    обработанные задачи, готовые для скачивания файлов
                    <div className="col-md-12 text-center">
                        <Spinner animation="border" role="status" variant="primary">
                            <span className="sr-only">Загрузка...</span>
                        </Spinner>
                    </div>
                </Modal.Body>
                <Modal.Footer>
                    <Button variant="outline-primary" onClick={this.props.handlerButtonSubmit} size="sm">
                        отправить
                    </Button>
                    <Button variant="outline-secondary" onClick={this.props.onHide} size="sm">
                        закрыть
                    </Button>
                </Modal.Footer>
            </Modal>
        );
    }
}

ModalWindowListTaskDownloadFiles.propTypes = {
    show: PropTypes.bool.isRequired,
    onHide: PropTypes.func.isRequired,
    handlerButtonSubmit: PropTypes.func.isRequired,
};