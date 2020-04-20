"use strict";

import React from "react";
import { Button, Col, Form, FormControl, Spinner, Row, Modal, InputGroup } from "react-bootstrap";
import PropTypes from "prop-types";

class ListFolder extends React.Component {
    constructor(props){
        super(props);

        this.listFolders = this.listFolders.bind(this);        
    }

    deleteNewFolder(folderName){
        this.props.handelerFolderDelete(folderName);
    }

    listFolders(){
        return this.props.directoriesNetworkTraffic.map((item) => {
            let num = 0;
            return <li key={`new_folder_${item}_${num++}`}>
                {item}&nbsp;
                <a onClick={this.deleteNewFolder.bind(this, item)} className="close" href="#"><img src="./images/icons8-delete-16.png"></img></a>
            </li>;
        });
    }

    render(){
        return <ol>{this.listFolders()}</ol>;
    }
}

ListFolder.propTypes = {
    handelerFolderDelete: PropTypes.func.isRequired,
    directoriesNetworkTraffic: PropTypes.array.isRequired,
};

class CreateBodySource extends React.Component {
    constructor(props){
        super(props);
    }

    render(){
        return (
            <Form validated={false}>
                <InputGroup className="mb-3">
                    <InputGroup.Prepend>
                        <InputGroup.Text>Источник</InputGroup.Text>
                    </InputGroup.Prepend>
                    <FormControl 
                        id="source_id" 
                        onChange={this.props.handlerInput.bind(this)}
                        isValid={this.props.storageInput.sourceID.isValid}
                        isInvalid={this.props.storageInput.sourceID.isInvalid}
                        defaultValue={this.props.storageInput.sourceID.value} />
                    <FormControl 
                        id="source_short_name" 
                        onChange={this.props.handlerInput.bind(this)}
                        isValid={this.props.storageInput.shortName.isValid}
                        isInvalid={this.props.storageInput.shortName.isInvalid}
                        defaultValue={this.props.storageInput.shortName.value} />               
                </InputGroup>
                <InputGroup className="mb-3">
                    <InputGroup.Prepend>
                        <InputGroup.Text>Сетевые настройки</InputGroup.Text>
                    </InputGroup.Prepend>
                    <FormControl 
                        id="source_ip" 
                        onChange={this.props.handlerInput.bind(this)}
                        isValid={this.props.storageInput.ipAddress.isValid}
                        isInvalid={this.props.storageInput.ipAddress.isInvalid}
                        defaultValue={this.props.storageInput.ipAddress.value} />
                    <FormControl 
                        id="source_port" 
                        onChange={this.props.handlerInput.bind(this)}
                        isValid={this.props.storageInput.port.isValid}
                        isInvalid={this.props.storageInput.port.isInvalid}
                        defaultValue={this.props.storageInput.port.value} />
                </InputGroup>
                <Form.Row>
                    <Form.Group as={Col}>
                        <Form.Label>Архитектура</Form.Label>
                        <Form.Control 
                            onChange={this.props.handlerInput.bind(this)}
                            id="source_architecture" 
                            as="select" 
                            defaultValue={this.props.storageInput.architecture.value}>
                            <option value="client">клиент</option>
                            <option value="server">сервер</option>
                        </Form.Control>
                    </Form.Group>
                    <Form.Group as={Col}>
                        <Form.Label>Параллельные задачи фильтрации</Form.Label>
                        <Form.Control 
                            onChange={this.props.handlerInput.bind(this)}
                            id="source_max_simultaneous_proc" 
                            as="select" 
                            defaultValue={this.props.storageInput.maxSimultaneousProc.value}>
                            {(() => {
                                let list = [];
                                for(let i = 1; i <= 10; i++){
                                    list.push(<option value={i} key={`tfo_${i}`}>{i}</option>);
                                }

                                return list;
                            })()
                            }
                        </Form.Control>
                    </Form.Group>
                </Form.Row>
                <Form.Row>
                    <Form.Group as={Col} lg={3}>
                        <Form.Label>Тип сетевого канала</Form.Label>
                        <Form.Control 
                            onChange={this.props.handlerInput.bind(this)}
                            id="source_network_channel"
                            as="select" 
                            defaultValue={this.props.storageInput.networkChannel.value}>
                            <option value="ip">ip/vlan</option>
                            <option value="pppoe">pppoe</option>
                        </Form.Control>
                    </Form.Group>
                    <Form.Group as={Col} lg={9}>
                        <Form.Label>Идентификационный токен</Form.Label>
                        <InputGroup.Append>
                            <Form.Control id="source_token" type="text" value={this.props.storageInput.token.value} readOnly />
                            <Button onClick={this.props.generatingNewToken} variant="outline-primary">новый</Button>
                        </InputGroup.Append>
                    </Form.Group>
                </Form.Row>
                <Row>
                    <Col lg={4}>
                        <Form.Check 
                            onChange={this.props.handlerInput.bind(this)}
                            defaultChecked={this.props.storageInput.telemetry.value}
                            type="switch"
                            id="source_telemetry" 
                            label="телеметрия"
                        />
                    </Col>
                    <Col lg={8}>
                        <InputGroup className="mb-3">
                            <FormControl
                                id="input_folder"
                                onChange={this.props.handlerInput.bind(this)}
                                isValid={this.props.storageInput.directoriesNetworkTraffic.isValid}
                                isInvalid={this.props.storageInput.directoriesNetworkTraffic.isInvalid}
                                placeholder="полный путь до директории с файлами" />
                            <InputGroup.Append>
                                <Button onClick={this.props.addNewFolder} variant="outline-secondary">применить</Button>
                            </InputGroup.Append>
                        </InputGroup>
                    </Col>
                </Row>
                <Row>
                    <Col lg={4}></Col>
                    <Col lg={8}>
                        <ListFolder 
                            handelerFolderDelete={this.props.handelerFolderDelete}
                            directoriesNetworkTraffic={this.props.storageInput.directoriesNetworkTraffic.value} />
                    </Col>
                </Row>
                <Form.Group>
                    <Form.Label>Примечание</Form.Label>
                    <Form.Control 
                        onChange={this.props.handlerInput.bind(this)}
                        defaultValue={this.props.storageInput.description.value}
                        id="source_description" 
                        as="textarea" 
                        rows="3" />
                </Form.Group>
            </Form>
        );
    }
}

CreateBodySource.propTypes = {
    addNewFolder: PropTypes.func.isRequired,
    handlerInput: PropTypes.func.isRequired, 
    storageInput: PropTypes.object.isRequired,
    generatingNewToken: PropTypes.func.isRequired,
    handelerFolderDelete: PropTypes.func.isRequired,
};

export default class ModalWindowChangeSource extends React.Component {
    constructor(props){
        super(props);

        this.state = { "receivedInformation": false };
        this.fullInformationAboutSource = {};

        this.windowClose = this.windowClose.bind(this);
    }

    windowClose(){
        this.props.onHide();
    }

    createMajorBody(){
        if(!this.props.isShowInfo){
            return (
                <div className="row">
                    <div className="col-md-12 text-center">
                        Источник №{this.props.settings.sourceID}, загрузка информации...
                    </div>
                    <div className="col-md-12 text-center">
                        <Spinner animation="border" role="status" variant="primary">
                            <span className="sr-only">Загрузка...</span>
                        </Spinner>
                    </div>
                </div>
            );
        }

        return (
            <Form validated={false}>
                <InputGroup className="mb-3">
                    <InputGroup.Prepend>
                        <InputGroup.Text>Источник</InputGroup.Text>
                    </InputGroup.Prepend>
                    <FormControl 
                        id="source_id" 
                        onChange={this.props.handlerInput.bind(this)}
                        isValid={this.props.storageInput.sourceID.isValid}
                        isInvalid={this.props.storageInput.sourceID.isInvalid}
                        defaultValue={this.props.storageInput.sourceID.value} />
                    <FormControl 
                        id="source_short_name" 
                        onChange={this.props.handlerInput.bind(this)}
                        isValid={this.props.storageInput.shortName.isValid}
                        isInvalid={this.props.storageInput.shortName.isInvalid}
                        defaultValue={this.props.storageInput.shortName.value} />               
                </InputGroup>
                <InputGroup className="mb-3">
                    <InputGroup.Prepend>
                        <InputGroup.Text>Сетевые настройки</InputGroup.Text>
                    </InputGroup.Prepend>
                    <FormControl 
                        id="source_ip" 
                        onChange={this.props.handlerInput.bind(this)}
                        isValid={this.props.storageInput.ipAddress.isValid}
                        isInvalid={this.props.storageInput.ipAddress.isInvalid}
                        defaultValue={this.props.storageInput.ipAddress.value} />
                    <FormControl 
                        id="source_port" 
                        onChange={this.props.handlerInput.bind(this)}
                        isValid={this.props.storageInput.port.isValid}
                        isInvalid={this.props.storageInput.port.isInvalid}
                        defaultValue={this.props.storageInput.port.value} />
                </InputGroup>
                <Form.Row>
                    <Form.Group as={Col}>
                        <Form.Label>Архитектура</Form.Label>
                        <Form.Control 
                            onChange={this.props.handlerInput.bind(this)}
                            id="source_architecture" 
                            as="select" 
                            defaultValue={this.props.storageInput.architecture.value}>
                            <option value="client">клиент</option>
                            <option value="server">сервер</option>
                        </Form.Control>
                    </Form.Group>
                    <Form.Group as={Col}>
                        <Form.Label>Параллельные задачи фильтрации</Form.Label>
                        <Form.Control 
                            onChange={this.props.handlerInput.bind(this)}
                            id="source_max_simultaneous_proc" 
                            as="select" 
                            defaultValue={this.props.storageInput.maxSimultaneousProc.value}>
                            {(() => {
                                let list = [];
                                for(let i = 1; i <= 10; i++){
                                    list.push(<option value={i} key={`tfo_${i}`}>{i}</option>);
                                }

                                return list;
                            })()
                            }
                        </Form.Control>
                    </Form.Group>
                </Form.Row>
                <Form.Row>
                    <Form.Group as={Col} lg={3}>
                        <Form.Label>Тип сетевого канала</Form.Label>
                        <Form.Control 
                            onChange={this.props.handlerInput.bind(this)}
                            id="source_network_channel"
                            as="select" 
                            defaultValue={this.props.storageInput.networkChannel.value}>
                            <option value="ip">ip/vlan</option>
                            <option value="pppoe">pppoe</option>
                        </Form.Control>
                    </Form.Group>
                    <Form.Group as={Col} lg={9}>
                        <Form.Label>Идентификационный токен</Form.Label>
                        <InputGroup.Append>
                            <Form.Control id="source_token" type="text" value={this.props.storageInput.token.value} readOnly />
                            <Button onClick={this.props.generatingNewToken} variant="outline-primary">новый</Button>
                        </InputGroup.Append>
                    </Form.Group>
                </Form.Row>
                <Row>
                    <Col lg={4}>
                        <Form.Check 
                            custom
                            defaultChecked={this.props.storageInput.telemetry.value}
                            onChange={this.props.handlerInput.bind(this)}
                            type="switch"
                            id="source_telemetry" 
                            label="телеметрия" />
                    </Col>
                    <Col lg={8}>
                        <InputGroup className="mb-3">
                            <FormControl
                                id="input_folder"
                                onChange={this.props.handlerInput.bind(this)}
                                isValid={this.props.storageInput.directoriesNetworkTraffic.isValid}
                                isInvalid={this.props.storageInput.directoriesNetworkTraffic.isInvalid}
                                placeholder="полный путь до директории с файлами" />
                            <InputGroup.Append>
                                <Button onClick={this.props.addNewFolder} variant="outline-secondary">применить</Button>
                            </InputGroup.Append>
                        </InputGroup>
                    </Col>
                </Row>
                <Row>
                    <Col lg={4}></Col>
                    <Col lg={8}>
                        <ListFolder 
                            handelerFolderDelete={this.props.handelerFolderDelete}
                            directoriesNetworkTraffic={this.props.storageInput.directoriesNetworkTraffic.value} />
                    </Col>
                </Row>
                <Form.Group>
                    <Form.Label>Примечание</Form.Label>
                    <Form.Control 
                        onChange={this.props.handlerInput.bind(this)}
                        defaultValue={this.props.storageInput.description.value}
                        id="source_description" 
                        as="textarea" 
                        rows="3" />
                </Form.Group>
            </Form>
        );
    }

    render(){
        return (
            <Modal
                size="lg"
                show={this.props.show} 
                onHide={this.windowClose}
                aria-labelledby="example-modal-sizes-title-lg" >
                <Modal.Header closeButton>
                    <Modal.Title id="example-modal-sizes-title-lg">
                        <h5>Редактировать источник №{this.props.settings.sourceID}</h5>
                    </Modal.Title>
                </Modal.Header>
                <Modal.Body>{this.createMajorBody.call(this)}</Modal.Body>
                <Modal.Footer>
                    <Button onClick={this.windowClose} variant="outline-secondary">закрыть</Button>
                    <Button onClick={this.props.handlerSaveInformation} variant="outline-success">сохранить</Button>
                </Modal.Footer>
            </Modal>
        );
    }
}

ModalWindowChangeSource.propTypes = {
    show: PropTypes.bool.isRequired,
    onHide: PropTypes.func.isRequired,
    settings: PropTypes.object.isRequired,
    isShowInfo: PropTypes.bool.isRequired,
    addNewFolder: PropTypes.func.isRequired,
    handlerInput: PropTypes.func.isRequired, 
    storageInput: PropTypes.object.isRequired,
    generatingNewToken: PropTypes.func.isRequired,
    handelerFolderDelete: PropTypes.func.isRequired,
    handlerSaveInformation: PropTypes.func.isRequired,
};