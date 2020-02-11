import React from "react";
import { Button, Col, Form, FormControl, Row, Modal, InputGroup } from "react-bootstrap";
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
                        onChange={this.props.handlerInput.bind(this, "source")}
                        isValid={this.props.storageInput.sourceID.isValid}
                        isInvalid={this.props.storageInput.sourceID.isInvalid}
                        placeholder="цифровой идентификатор" />
                    <FormControl 
                        id="source_short_name" 
                        onChange={this.props.handlerInput.bind(this, "source")}
                        isValid={this.props.storageInput.shortName.isValid}
                        isInvalid={this.props.storageInput.shortName.isInvalid}
                        placeholder="краткое название (анг. алфавит)" />               
                </InputGroup>
                <InputGroup className="mb-3">
                    <InputGroup.Prepend>
                        <InputGroup.Text>Сетевые настройки</InputGroup.Text>
                    </InputGroup.Prepend>
                    <FormControl 
                        id="source_ip" 
                        onChange={this.props.handlerInput.bind(this, "source")}
                        isValid={this.props.storageInput.ipAddress.isValid}
                        isInvalid={this.props.storageInput.ipAddress.isInvalid}
                        placeholder="ip адрес" />
                    <FormControl 
                        id="source_port" 
                        onChange={this.props.handlerInput.bind(this, "source")}
                        isValid={this.props.storageInput.port.isValid}
                        isInvalid={this.props.storageInput.port.isInvalid}
                        placeholder="сетевой порт" />
                </InputGroup>
                <Form.Row>
                    <Form.Group as={Col}>
                        <Form.Label>Архитектура</Form.Label>
                        <Form.Control 
                            onChange={this.props.handlerInput.bind(this, "source")}
                            isValid={this.props.storageInput.architecture.isValid}
                            isInvalid={this.props.storageInput.architecture.isInvalid}
                            id="source_architecture" 
                            as="select" 
                            defaultValue="client">
                            <option value="client">клиент</option>
                            <option value="server">сервер</option>
                        </Form.Control>
                    </Form.Group>
                    <Form.Group as={Col}>
                        <Form.Label>Параллельные задачи фильтрации</Form.Label>
                        <Form.Control 
                            onChange={this.props.handlerInput.bind(this, "source")}
                            isValid={this.props.storageInput.maxSimultaneousProc.isValid}
                            isInvalid={this.props.storageInput.maxSimultaneousProc.isInvalid}
                            id="source_max_simultaneous_proc" 
                            as="select" 
                            defaultValue="5">
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
                    <Form.Group as={Col}>
                        <Form.Label>Тип сетевого канала</Form.Label>
                        <Form.Control 
                            onChange={this.props.handlerInput.bind(this, "source")}
                            isValid={this.props.storageInput.networkChannel.isValid}
                            isInvalid={this.props.storageInput.networkChannel.isInvalid}
                            id="source_network_channel"
                            as="select" 
                            defaultValue="ip">
                            <option value="ip">ip/vlan</option>
                            <option value="pppoe">pppoe</option>
                        </Form.Control>
                    </Form.Group>
                    <Form.Group as={Col}>
                        <Form.Label>Идентификационный токен</Form.Label>
                        <Form.Control id="source_token" type="text" readOnly defaultValue={this.props.storageInput.token.value} />
                    </Form.Group>
                </Form.Row>
                <Row>
                    <Col lg={4}>
                        <Form.Check 
                            onChange={this.props.handlerInput.bind(this, "source")}
                            isValid={this.props.storageInput.telemetry.isValid}
                            isInvalid={this.props.storageInput.telemetry.isInvalid}
                            type="switch"
                            id="source_telemetry" 
                            label="телеметрия"
                        />
                    </Col>
                    <Col lg={8}>
                        <InputGroup className="mb-3">
                            <FormControl
                                id="input_folder"
                                onChange={this.props.handlerInput.bind(this, "source")}
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
                        onChange={this.props.handlerInput.bind(this, "source")}
                        isValid={this.props.storageInput.description.isValid}
                        isInvalid={this.props.storageInput.description.isInvalid}
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
    handelerFolderDelete: PropTypes.func.isRequired,
};

export default class ModalWindowChangeSource extends React.Component {
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
                <Modal.Body>
                    <CreateBodySource 
                        addNewFolder={this.props.addNewFolder}
                        handlerInput={this.props.handlerInput} 
                        storageInput={this.props.storageInput}
                        handelerFolderDelete={this.props.handelerFolderDelete} />
                </Modal.Body>
                <Modal.Footer>
                    <Button onClick={this.windowClose} variant="outline-secondary">закрыть</Button>
                    <Button onClick={this.buttonAdd} variant="outline-primary">добавить</Button>
                </Modal.Footer>
            </Modal>
        );
    }
}

ModalWindowChangeSource.propTypes = {
    show: PropTypes.bool,
    onHide: PropTypes.func,
    settings: PropTypes.object,
    addNewFolder: PropTypes.func.isRequired,
    handlerInput: PropTypes.func.isRequired, 
    storageInput: PropTypes.object.isRequired,
    handelerFolderDelete: PropTypes.func.isRequired,
};