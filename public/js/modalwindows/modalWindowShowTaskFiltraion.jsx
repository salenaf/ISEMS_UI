"use strict";

import React from "react";
import { Button, Modal, Spinner } from "react-bootstrap";
import PropTypes from "prop-types";

export default class ModalWindowShowTaskFiltraion extends React.Component {
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
                        <h5>Информация по задаче, выполняемой на источнике №{this.props.shortTaskInfo.sourceID} ({this.props.shortTaskInfo.sourceName})</h5>
                    </Modal.Title>
                </Modal.Header>
                <Modal.Body>
                    сама информация
                    <div className="col-md-12 text-center">
                        <Spinner animation="border" role="status" variant="primary">
                            <span className="sr-only">Загрузка...</span>
                        </Spinner>
                    </div>
                </Modal.Body>
                <Modal.Footer>
                    <Button variant="outline-danger" onClick={this.props.handlerButtonStopFiltering} size="sm">
                        отменить
                    </Button>
                    <Button variant="outline-secondary" onClick={this.props.onHide} size="sm">
                        закрыть
                    </Button>
                </Modal.Footer>
            </Modal>
        );
    }
}

ModalWindowShowTaskFiltraion.propTypes = {
    show: PropTypes.bool.isRequired,
    onHide: PropTypes.func.isRequired,
    shortTaskInfo: PropTypes.object.isRequired,
    handlerButtonStopFiltering: PropTypes.func.isRequired,
};