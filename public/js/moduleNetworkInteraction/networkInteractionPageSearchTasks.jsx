import React from "react";
import ReactDOM from "react-dom";
import { Button, Col, Row, Table, Form, Pagination, Tooltip, OverlayTrigger } from "react-bootstrap";
import PropTypes from "prop-types";

import GetStatusDownload from "../commons/getStatusDownload.jsx";
import GetStatusFiltering from "../commons/getStatusFiltering.jsx";
import CreateBodySearchTask from "./createBodySearchTask.jsx";
import ListNetworkParameters from "../commons/listNetworkParameters.jsx";
import { ModalWindowConfirmMessage } from "../modalwindows/modalWindowConfirmMessage.jsx";
import ModalWindowShowInformationTask from "../modalwindows/modalWindowShowInformationTask.jsx";

class CreatePageSearchTasks extends React.Component {
    constructor(props){
        super(props);

        this.state = {
            shortTaskInformation: { 
                sourceID: 0, 
                sourceName: "",
                taskID: "",
            },
            showModalWindowDeleteTask: false,
            showModalWindowShowTaskInformation: false,
            listCheckboxMarkedTasksDel: new Set(),
            listTasksFound: {
                p: { cs: 0, cn: 0, ccn: 1 },
                slft: [],
                tntf: 0,            
            },
        };

        this.handlerEvents.call(this);
        this.requestEmitter.call(this);

        this.getUserPermission = this.getUserPermission.bind(this);
        this.handlerTaskDelete = this.handlerTaskDelete.bind(this);
        this.createTableListDownloadFile = this.createTableListDownloadFile.bind(this);
        this.closeModalWindowTasksDelete = this.closeModalWindowTasksDelete.bind(this);
        this.handlerModalWindowShowTaskTnformation = this.handlerModalWindowShowTaskTnformation.bind(this);
        this.handlerShowModalWindowShowTaskInformation = this.handlerShowModalWindowShowTaskInformation.bind(this);
        this.handlerCloseModalWindowShowTaskInformation=this.handlerCloseModalWindowShowTaskInformation.bind(this);
    }

    requestEmitter(){
        this.props.socketIo.emit("network interaction: get list all tasks", { arguments: {} });   
    }

    getUserPermission(){
        return this.props.listItems.userPermissions;
    }

    handlerEvents(){
        this.props.socketIo.on("module NI API", (data) => {
            if(data.type === "send a list of found tasks"){

                console.log("--- event: send a list of found issues ---");
                console.log(data.options);
    
                let tmpCopy = Object.assign(this.state.listTasksFound);
                tmpCopy = { 
                    p: data.options.p,
                    slft: data.options.slft, 
                    tntf: data.options.tntf,
                };
                this.setState({ listTasksFound: tmpCopy });
            }
        });
    }

    handlerModalWindowShowTaskTnformation(data){

        console.log("func 'handlerModalWindowShowTaskTnformation'...");
        console.log(data);

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

    headerClickTable(objData, type, e){
        if(type === "info"){
            this.handlerModalWindowShowTaskTnformation(objData);
            
            this.props.socketIo.emit("network interaction: show info about all task", {
                arguments: { taskID: objData.taskID } 
            });
        }
        
        if(type === "re-filtering"){
            //повторная фильтрация
            /**
             * Открыть модальное окно фильтрации с 
             * уже заполненными параметрами
             * 
             */
        }

        if(type === "delete"){
            if(this.state.listCheckboxMarkedTasksDel.size === 0){
                return;
            }

            this.setState({ showModalWindowDeleteTask: true });
        }
    }

    headerNextItemPagination(num){
        if(this.state.listTasksFound.p.ccn === num){
            return;
        }

        this.props.socketIo.emit("network interaction: get next chunk list all tasks", {
            taskID: this.state.currentTaskID,
            chunkSize: this.state.listTasksFound.p.cs,
            nextChunk: num,
        });
    }

    handlerTaskDelete(){
        console.log("func 'handlerTaskDelete', START...");

        /**
        * 
        * Данная функция пока не реализована ни в ISEMS-UI,
        * ни в ISEMS-NIH_master. Требуется дополнительная
        * реализация.
        * 
        */

    }

    closeModalWindowTasksDelete(){
        this.setState({ showModalWindowDeleteTask: false });
    }

    isDisabledDelete(){       
        if(!this.getUserPermission().management_tasks_filter.element_settings.delete.status){
            return "disabled";
        }

        return (this.state.listCheckboxMarkedTasksDel.size > 0) ? "" : "disabled";
    }

    changeCheckboxMarked(tid, e){ 
        let lcmtd = this.state.listCheckboxMarkedTasksDel;
        if(e.target.checked){
            lcmtd.add(tid);
        } else {
            lcmtd.delete(tid);
        }
                
        this.setState({ listCheckboxMarkedTasksDel: lcmtd });
    }

    createTableListDownloadFile(){
        let createTableBody = () => {
            if((typeof this.state.listTasksFound.slft === "undefined") || (this.state.listTasksFound.slft.length === 0)){
                return;
            }

            let num = 0;
            if(this.state.listTasksFound.p.ccn > 1){
                num = (this.state.listTasksFound.p.ccn - 1) * this.state.listTasksFound.p.cs;
            }

            let tableBody = [];
            let formatterDate = new Intl.DateTimeFormat("ru-Ru", {
                timeZone: "Europe/Moscow",
                day: "numeric",
                month: "numeric",
                year: "numeric",
                hour: "numeric",
                minute: "numeric",
            });

            this.state.listTasksFound.slft.forEach((item) => {
                let dataInfo = { taskID: item.tid, sourceID: item.sid, sourceName: item.sn };

                tableBody.push(<tr key={`tr_${item.tid}`}>
                    <td className="align-middle clicabe_cursor" onClick={this.headerClickTable.bind(this, dataInfo, "info")} key={`tr_${item.tid}_num`}>
                        <small>{`${++num}.`}</small>
                    </td>
                    <td className="align-middle clicabe_cursor text-info" onClick={this.headerClickTable.bind(this, dataInfo, "info")} key={`tr_${item.tid}_sourceID`}>
                        <small>{item.sid}</small>
                    </td>
                    <td className="align-middle my_line_spacing clicabe_cursor" onClick={this.headerClickTable.bind(this, dataInfo, "info")} key={`tr_${item.tid}_sourceName`}>
                        <small>{item.sn}</small>
                    </td>
                    <td className="align-middle my_line_spacing clicabe_cursor" onClick={this.headerClickTable.bind(this, dataInfo, "info")} key={`tr_${item.tid}_time_begin`}>
                        <div><small className="text-info">{formatterDate.format(item.stte*1000)}</small></div>
                    </td>
                    <td className="align-middle my_line_spacing clicabe_cursor" onClick={this.headerClickTable.bind(this, dataInfo, "info")} key={`tr_${item.tid}_time`}>
                        <div><small>{formatterDate.format(item.pf.dt.s*1000)}</small></div>
                        <div><small>{formatterDate.format(item.pf.dt.e*1000)}</small></div>
                    </td>
                    <td className="my_line_spacing clicabe_cursor" onClick={this.headerClickTable.bind(this, dataInfo, "info")} key={`tr_${item.tid}_ip`}>
                        <small><ListNetworkParameters type={"ip"} item={item.pf.f.ip} /></small>
                    </td>
                    <td className="my_line_spacing clicabe_cursor" onClick={this.headerClickTable.bind(this, dataInfo, "info")} key={`tr_${item.tid}_network`}>
                        <small><ListNetworkParameters type={"nw"} item={item.pf.f.nw} /></small>
                    </td>
                    <td className="my_line_spacing clicabe_cursor" onClick={this.headerClickTable.bind(this, dataInfo, "info")} key={`tr_${item.tid}_port`}>
                        <small><ListNetworkParameters type={"pt"} item={item.pf.f.pt} /></small>
                    </td>
                    <td className="my_line_spacing align-middle clicabe_cursor" onClick={this.headerClickTable.bind(this, dataInfo, "info")} key={`tr_${item.tid}_sf`}>
                        <small><GetStatusFiltering status={item.fts} /></small>
                    </td>
                    <td className="my_line_spacing align-middle clicabe_cursor" onClick={this.headerClickTable.bind(this, dataInfo, "info")} key={`tr_${item.tid}_sd`}>
                        <small><GetStatusDownload status={item.fdts} /></small>
                    </td>
                    <td className="align-middle">
                        <Button 
                            size="sm" 
                            variant="outline-light" >
                            <a href="#">
                                <img className="clickable_icon" src="../images/icons8-repeat-24.png" alt="выполнить повторную фильтрацию"></img>
                            </a>
                        </Button>
                    </td>
                    <td className="align-middle">
                        <OverlayTrigger
                            key={`tooltip_${item.tid}_checkbox`}
                            placement="right"
                            overlay={<Tooltip>отметить для удаления</Tooltip>}>
                            <Form>
                                <Form.Check 
                                    className="mt-1"
                                    custom 
                                    onChange={this.changeCheckboxMarked.bind(this, item.tid)}
                                    type="checkbox" 
                                    id={`checkbox-${item.tid}`}
                                    label="" />
                            </Form>
                        </OverlayTrigger>
                    </td>
                </tr>);
            });

            return tableBody;
        };

        if(this.state.listTasksFound.tntf === 0){
            return (
                <React.Fragment>
                    <Row className="pt-4">
                        <Col md={10} className="text-left text-muted">
                        всего задач найдено: <i>{this.state.listTasksFound.tntf}</i>
                        </Col>
                        <Col md={2} className="text-right"></Col>
                    </Row>
                </React.Fragment>
            );        
        }

        return (
            <React.Fragment>
                <Row className="pt-4">
                    <Col md={10} className="text-left text-muted">
                    всего задач найдено: <i>{this.state.listTasksFound.tntf}</i>
                    </Col>
                    <Col md={2} className="text-right">
                        <Button 
                            size="sm" 
                            variant="outline-danger"
                            disabled={this.isDisabledDelete.call(this)}
                            onClick={this.headerClickTable.bind(this, {}, "delete")} >
                            удалить
                        </Button>
                    </Col>
                </Row>
                <Row className="py-2">
                    <Col md={12}>
                        <Table size="sm" striped hover>
                            <thead>
                                <tr>
                                    <th></th>
                                    <th>ID</th>
                                    <th>название</th>
                                    <th>задача добавлена</th>
                                    <th>интервал времени</th>
                                    <th>ip</th>
                                    <th>network</th>
                                    <th>port</th>
                                    <th>фильтрация</th>
                                    <th>выгрузка</th>
                                    <th></th>
                                </tr>
                            </thead>
                            <tbody>
                                {createTableBody()}
                            </tbody>
                        </Table>
                    </Col>
                </Row>
            </React.Fragment>
        );
    }

    createPagination(){
        if(this.state.listTasksFound.p.cn <= 1){
            return;
        }

        let listItem = [];
        for(let i = 1; i < this.state.listTasksFound.p.cn+1; i++){       
            listItem.push(
                <Pagination.Item 
                    key={`pag_${i}`} 
                    active={this.state.listTasksFound.p.ccn === i}
                    onClick={this.headerNextItemPagination.bind(this, i)} >
                    {i}
                </Pagination.Item>
            );
        }

        return (
            <Row>
                <Col md={12} className="d-flex justify-content-center">
                    <Pagination size="sm">{listItem}</Pagination>
                </Col>
            </Row>
        );
    }

    render(){
        let createPagination = this.createPagination.call(this);

        return (
            <React.Fragment>
                <Row>
                    <Col md={12} className="text-left text-muted">поиск задач</Col>
                </Row>
                <CreateBodySearchTask 
                    socketIo={this.props.socketIo} 
                    listSources={this.props.listItems.listSources} />
                {this.createTableListDownloadFile.call(this)}
                {createPagination}
                <ModalWindowShowInformationTask 
                    show={this.state.showModalWindowShowTaskInformation}
                    onHide={this.handlerCloseModalWindowShowTaskInformation}
                    socketIo={this.props.socketIo}
                    shortTaskInfo={this.state.shortTaskInformation} />
                <ModalWindowConfirmMessage 
                    show={this.state.showModalWindowDeleteTask}
                    onHide={this.closeModalWindowTasksDelete}
                    msgBody={`Вы действительно хотите удалить ${(this.state.listCheckboxMarkedTasksDel.size > 1) ? "выбранные задачи": "выбранную задачу"}`}
                    msgTitle={"Удаление"}
                    nameDel={""}
                    handlerConfirm={this.handlerTaskDelete} />
            </React.Fragment>
        );
    }
}

CreatePageSearchTasks.propTypes = {
    socketIo: PropTypes.object.isRequired,
    listItems: PropTypes.object.isRequired,
}; 

ReactDOM.render(<CreatePageSearchTasks
    socketIo={socket}
    listItems={receivedFromServer} />, document.getElementById("main-page-content"));