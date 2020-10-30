import React from "react";
import ReactDOM from "react-dom";
import { Col, Row, Table, Pagination } from "react-bootstrap";
import PropTypes from "prop-types";

import GetStatusDownload from "../commons/getStatusDownload.jsx";
import GetStatusFiltering from "../commons/getStatusFiltering.jsx";
import CreateBodySearchTask from "./createBodySearchTask.jsx";
import ListNetworkParameters from "../commons/listNetworkParameters.jsx";
import ModalWindowShowInformationTask from "../modalwindows/modalWindowShowInformationTask.jsx";


export default class CreatePageStatisticsAndAnalytics extends React.Component {
    constructor(props){
        super(props);

        this.state = {
            shortTaskInformation: { 
                sourceID: 0, 
                sourceName: "",
                taskID: "",
            },
            showModalWindowShowTaskInformation: false,
            listTasksFound: {
                p: { cs: 0, cn: 0, ccn: 1 },
                slft: [],
                tntf: 0,            
            },
        };

        this.userPermission=this.props.listItems.userPermissions;

        this.handlerEvents.call(this);

        this.createTableListDownloadFile = this.createTableListDownloadFile.bind(this);
        this.handlerModalWindowShowTaskTnformation = this.handlerModalWindowShowTaskTnformation.bind(this);
        this.handlerShowModalWindowShowTaskInformation = this.handlerShowModalWindowShowTaskInformation.bind(this);
        this.handlerCloseModalWindowShowTaskInformation=this.handlerCloseModalWindowShowTaskInformation.bind(this);
    }

    handlerEvents(){
        this.props.socketIo.on("module NI API", (data) => {
            //для списка задач не отмеченных пользователем как завершеные
            if(data.type === "get list unresolved task"){

                console.log("--- event: get list unresolved task ---");
                console.log(data.options);
    
                if(data.options.tntf === 0){
                    return;
                }

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
        
        if(type === "processed"){
            //отметить как обработанную

        }


    }

    headerNextItemPagination(){

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
            let formaterInt = new Intl.NumberFormat();

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
                    <td className="align-middle my_line_spacing clicabe_cursor" onClick={this.headerClickTable.bind(this, dataInfo, "info")} key={`tr_${item.tid}_time`}>
                        <div><small>{formatterDate.format(item.pf.dt.s*1000)}</small></div>
                        <div><small>{formatterDate.format(item.pf.dt.e*1000)}</small></div>
                    </td>
                    <td className="my_line_spacing clicabe_cursor" onClick={this.headerClickTable.bind(this, dataInfo, "info")} key={`tr_${item.tid}_ip`}>
                        <small><ListNetworkParameters type={"ip"} item={item.pf.f.ip} listInput={[]} /></small>
                    </td>
                    <td className="my_line_spacing clicabe_cursor" onClick={this.headerClickTable.bind(this, dataInfo, "info")} key={`tr_${item.tid}_network`}>
                        <small><ListNetworkParameters type={"nw"} item={item.pf.f.nw} listInput={[]} /></small>
                    </td>
                    <td className="my_line_spacing clicabe_cursor" onClick={this.headerClickTable.bind(this, dataInfo, "info")} key={`tr_${item.tid}_port`}>
                        <small><ListNetworkParameters type={"pt"} item={item.pf.f.pt} listInput={[]} /></small>
                    </td>
                    <td className="my_line_spacing align-middle clicabe_cursor" onClick={this.headerClickTable.bind(this, dataInfo, "info")} key={`tr_${item.tid}_sf`}>
                        <small><GetStatusFiltering status={item.fts} /></small>
                    </td>
                    <td className="my_line_spacing align-middle clicabe_cursor" onClick={this.headerClickTable.bind(this, dataInfo, "info")} key={`tr_${item.tid}_sd`}>
                        <small><GetStatusDownload status={item.fdts} /></small>
                    </td>
                    <td className="align-middle clicabe_cursor" onClick={this.headerClickTable.bind(this, dataInfo, "info")} key={`tr_${item.tid}_search_file`}>
                        <small>{`${formaterInt.format(item.nffarf)} (${formaterInt.format(item.nfd)})`}</small>
                    </td>
                    <td className="align-middle clicabe_cursor" onClick={this.headerClickTable.bind(this, dataInfo, "info")} key={`tr_${item.tid}_size_search_files`}>
                        <small>{`${formaterInt.format(item.tsffarf)} байт.`}</small>
                    </td>
                    <td className="align-middle" onClick={this.headerClickTable.bind(this, dataInfo, "processed")}>
                        <a href="#">
                            <img className="clickable_icon" src="../images/icons8-checkmark-24.png" alt="отметить как обработанную"></img>
                        </a>
                    </td>
                </tr>);
            });

            return tableBody;
        };

        if(this.state.listTasksFound.tntf === 0){
            return (
                <React.Fragment>
                    <Row className="py-2"></Row>    
                </React.Fragment>
            );        
        }

        return (
            <Row className="py-2">
                <Col>
                    <Table size="sm" striped hover>
                        <thead>
                            <tr>
                                <th></th>
                                <th>ID</th>
                                <th>название</th>
                                <th className="my_line_spacing">интервал времени</th>
                                <th>ip</th>
                                <th>network</th>
                                <th>port</th>
                                <th>фильтрация</th>
                                <th>выгрузка</th>
                                <th className="my_line_spacing">файлы найденны (выгружены)</th>
                                <th className="my_line_spacing">общим размером</th>
                                <th></th>
                            </tr>
                        </thead>
                        <tbody>
                            {createTableBody()}
                        </tbody>
                    </Table>
                </Col>
            </Row>    
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
                    <Col md={12} className="text-left text-muted">статистика и аналитика</Col>
                </Row>
                {createPagination}
                {this.createTableListDownloadFile.call(this)}
                {createPagination}
                <ModalWindowShowInformationTask 
                    show={this.state.showModalWindowShowTaskInformation}
                    onHide={this.handlerCloseModalWindowShowTaskInformation}
                    socketIo={this.props.socketIo}
                    shortTaskInfo={this.state.shortTaskInformation} />
            </React.Fragment>
        );
    }
}

CreatePageStatisticsAndAnalytics.propTypes = {
    socketIo: PropTypes.object.isRequired,
    listItems: PropTypes.object.isRequired,
};

ReactDOM.render(<CreatePageStatisticsAndAnalytics
    socketIo={socket}
    listItems={receivedFromServer} />, document.getElementById("main-page-content"));
