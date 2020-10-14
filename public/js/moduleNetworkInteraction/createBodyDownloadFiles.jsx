import React from "react";
import { Col, Row, Table, Pagination } from "react-bootstrap";
import PropTypes from "prop-types";

import ListNetworkParameters from "../commons/listNetworkParameters.jsx";

export default class CreateBodyDownloadFiles extends React.Component {
    constructor(props){
        super(props);

        this.state = {
            currentTaskID: "",
            listFileDownloadOptions: {
                p: { cs: 0, cn: 0, ccn: 1 },
                slft: [],
                tntf: 0,
            },
        };
        
        this.headerEvents.call(this);
    }
   
    headerEvents(){
        this.props.socketIo.on("module NI API", (data) => {
            if(data.type === "get list tasks files not downloaded"){
                this.setState({ 
                    currentTaskID: data.taskID,
                    listFileDownloadOptions: data.options, 
                });
            }
        });

        this.props.socketIo.on("module NI API", (msg) => {
            if((msg.type === "filtrationProcessing") || (msg.type === "downloadProcessing")){          
                if(msg.options.status !== "complete"){
                    return;
                }

                this.props.socketIo.emit("network interaction: get list tasks to download files", { arguments: {} });
            }
        });
    }

    headerClickTable(objData, type, e){
        if(type === "info"){
            this.props.handlerModalWindowShowTaskTnformation(objData);
            
            this.props.socketIo.emit("network interaction: show info about all task", {
                arguments: { taskID: objData.taskID } 
            });
        } else {
            this.props.handlerShowModalWindowListFileDownload(objData);

            this.props.socketIo.emit("network interaction: get a list of files for a task", {
                arguments: { 
                    taskID: objData.taskID,
                    partSize: 25,
                    offsetListParts: 0,
                } 
            });
        }
    }

    headerNextItemPagination(num){
        if(this.state.listFileDownloadOptions.p.ccn === num){
            return;
        }

        this.props.socketIo.emit("network interaction: get next chunk list tasks files not downloaded", {
            taskID: this.state.currentTaskID,
            chunkSize: this.state.listFileDownloadOptions.p.cs,
            nextChunk: num,
        });
    }

    createPagination(){
        if(this.state.listFileDownloadOptions.p.cn <= 1){
            return;
        }

        let listItem = [];
        for(let i = 1; i < this.state.listFileDownloadOptions.p.cn+1; i++){       
            listItem.push(
                <Pagination.Item 
                    key={`pag_${i}`} 
                    active={this.state.listFileDownloadOptions.p.ccn === i}
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

    createTableListDownloadFile(){
        let createTableBody = () => {
            if((typeof this.state.listFileDownloadOptions.slft === "undefined") || (this.state.listFileDownloadOptions.slft.length === 0)){
                return;
            }

            let num = 0;
            if(this.state.listFileDownloadOptions.p.ccn > 1){
                num = (this.state.listFileDownloadOptions.p.ccn - 1) * this.state.listFileDownloadOptions.p.cs;
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

            this.state.listFileDownloadOptions.slft.forEach((item) => {
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
                    <td className="align-middle my_line_spacing clicabe_cursor" onClick={this.headerClickTable.bind(this, dataInfo, "info")} key={`tr_${item.tid}_proto`}>
                        <small>{item.pf.p}</small>
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
                    <td className="align-middle clicabe_cursor" onClick={this.headerClickTable.bind(this, dataInfo, "info")} key={`tr_${item.tid}_search_file`}>
                        <small>{`${formaterInt.format(item.nffarf)} (${formaterInt.format(item.nfd)})`}</small>
                    </td>
                    <td className="align-middle clicabe_cursor" onClick={this.headerClickTable.bind(this, dataInfo, "info")} key={`tr_${item.tid}_size_search_files`}>
                        <small>{`${formaterInt.format(item.tsffarf)} байт.`}</small>
                    </td>
                    <td className="align-middle" onClick={this.headerClickTable.bind(this, dataInfo, "download")}>
                        <a href="#">
                            <img className="clickable_icon" src="../images/icons8-download-from-the-cloud-32.png" alt="скачать"></img>
                        </a>
                    </td>
                </tr>);
            });

            return tableBody;
        };

        if(this.state.listFileDownloadOptions.tntf === 0){
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
                                <th className="my_line_spacing">сет. протокол</th>
                                <th>ip</th>
                                <th>network</th>
                                <th>port</th>
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

    render(){
        let createPagination = this.createPagination.call(this);

        return (
            <React.Fragment>
                <Row className="text-right">
                    <Col className="text-muted mt-3">
                    задач, по которым не выполнялась выгрузка файлов: <span className="text-info">{this.state.listFileDownloadOptions.tntf}</span>
                    </Col>
                </Row>
                {createPagination}
                {this.createTableListDownloadFile.call(this)}
                {createPagination}
            </React.Fragment>
        );
    }
}


CreateBodyDownloadFiles.propTypes = {
    socketIo: PropTypes.object.isRequired,
    handlerModalWindowShowTaskTnformation: PropTypes.func.isRequired,
    handlerShowModalWindowListFileDownload: PropTypes.func.isRequired,
};