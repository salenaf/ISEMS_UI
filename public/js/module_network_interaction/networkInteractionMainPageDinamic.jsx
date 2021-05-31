import React from "react";
import ReactDOM from "react-dom";
import { Col, Row } from "react-bootstrap";
import PropTypes from "prop-types";

import CreateBodyDynamics from "./createBodyDynamics.jsx";
import ModalWindowShowInformationTask from "../modal_windows/modalWindowShowInformationTask.jsx";

import { CreateListEntity } from "../settings/organizations_and_sources/createBodyManagementEntity.jsx";

class CreatePageDimanic extends React.Component {
    constructor(props){
        super(props);

        this.state = {
            shortTaskInformation: { 
                sourceID: 0, 
                sourceName: "",
                taskID: "",
            },
            showModalWindowShowTaskInformation: false,
        };

        this.handlerModalWindowShowTaskTnformation = this.handlerModalWindowShowTaskTnformation.bind(this);
        this.handlerShowModalWindowShowTaskInformation = this.handlerShowModalWindowShowTaskInformation.bind(this);
        this.handlerCloseModalWindowShowTaskInformation=this.handlerCloseModalWindowShowTaskInformation.bind(this);
    
        this.tmpList = {
            shortListDivision: [
                {source_list: Array(0), id: "04c83b09321869a9887d804d0ca51", id_organization: "4cc9c5679bb843631592d154d565", name: "Главное управление заводом"},
                {source_list: Array(1), id: "2b5add69cb563572ca088670a58", id_organization: "4cc9c5679bb843631592d154d565", name: "Цех №1"},
            ],
            shortListOrganization: [
                {division_or_branch_list_id: Array(4), id: "4cc9c5679bb843631592d154d565", name: "АвтоЗавод", field_activity: "коммерческая деятельность"},
                {division_or_branch_list_id: Array(1), id: "68c2066525a2933c2ca192197426", name: "Первая тестовая организация IT (им. Спайдермена)", field_activity: "наука и образование"},
            ],
            shortListSource: [
                {
                    connect_status: true,
                    connect_time: 1611731250,
                    date_register: 1603981817847,
                    id: "b46720c197285d36935c9c5c289a5",
                    id_division: "32681abb89ddc1b838954a7282b64",
                    information_about_app: {version: "v1.5.3", date: "26.01.2021"},
                    short_name: "Test Source 1",
                    source_id: 1000,
                },
                {
                    connect_status: false,
                    connect_time: 0,
                    date_register: 1609239867997,
                    id: "a40762730400a7c1d837d7b9a749",
                    id_division: "2b5add69cb563572ca088670a58",
                    information_about_app: {version: "не определена", date: "не определено"},
                    short_name: "Test 13333",
                    source_id: 13333,
                },
            ],
        };
    }

    handlerSelected1(){

    }

    handlerModalWindowShowTaskTnformation(data){
        let objCopy = Object.assign({}, this.state);
        objCopy.shortTaskInformation.sourceID = data.sourceID;
        objCopy.shortTaskInformation.sourceName = data.sourceName;
        objCopy.shortTaskInformation.taskID = data.taskID;
        this.setState(objCopy);

        this.handlerShowModalWindowShowTaskInformation();
    }

    handlerShowModalWindowShowTaskInformation(){
        this.setState({ showModalWindowShowTaskInformation: true });
    }


    handlerCloseModalWindowShowTaskInformation(){
        this.setState({ showModalWindowShowTaskInformation: false });
    }

    render(){
        return (
            <React.Fragment>
                <Row className="pt-3">
                    <Col md={12}>
                        <CreateBodyDynamics 
                            socketIo={this.props.socketIo}
                            handlerModalWindowShowTaskTnformation={this.handlerModalWindowShowTaskTnformation} />
                    </Col>
                </Row>

                <Row className="justify-content-md-center"> 
                    <Col className="text-left" md="auto">
                        <CreateListEntity 
                            listShortEntity={this.tmpList}
                            handlerSelected={this.handlerSelected1} />  
                    </Col>
                </Row>
                
                <ModalWindowShowInformationTask 
                    show={this.state.showModalWindowShowTaskInformation}
                    onHide={this.handlerCloseModalWindowShowTaskInformation}
                    socketIo={this.props.socketIo}
                    shortTaskInfo={this.state.shortTaskInformation} />
            </React.Fragment>
        );
    }
}

CreatePageDimanic.propTypes = {
    socketIo: PropTypes.object.isRequired,
    listItems: PropTypes.object.isRequired,
}; 

ReactDOM.render(<CreatePageDimanic
    socketIo={socket}
    listItems={receivedFromServer} />, document.getElementById("main-page-content"));