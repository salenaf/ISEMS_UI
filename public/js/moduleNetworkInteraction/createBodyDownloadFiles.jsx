import React from "react";
import { Col, Row, Table, Tooltip, OverlayTrigger, Pagination } from "react-bootstrap";
import PropTypes from "prop-types";

export default class CreateBodyDownloadFiles extends React.Component {
    constructor(props){
        super(props);

        this.state = {
            currentTaskID: "",
            listFileDownloadOptions: {
                p: { cs: 0, cn: 0, ccn: 0 },
                slft: [],
                tntf: 0,
            },
            currentNumPagination: 1,
        };

        this.getListNetworkParameters = this.getListNetworkParameters.bind(this);
        
        this.headerEvents.call(this);
    }
   
    headerEvents(){
        this.props.socketIo.on("module NI API", (data) => {
            if(data.type === "get list tasks files not downloaded"){

                console.log(data);
    
                this.setState({ 
                    currentTaskID: data.taskID,
                    listFileDownloadOptions: data.options 
                });
            }
        });
    }

    headerClickTable(objData, type, e){
        console.log("func 'headerClickTable'");
        console.log(`task ID: ${objData.taskID}`);
        console.log(`source ID: ${objData.sourceID}`);
        console.log(`type: ${type}`);
        console.log(e);

        if(type === "info"){
            this.props.handlerModalWindowShowTaskTnformation(objData);
            
            this.props.socketIo.emit("network interaction: show info about all task", {
                arguments: { taskID: objData.taskID } 
            });
        } else {
            console.log("download");
        }
    }

    headerNextItemPagination(num){
        console.log("func 'headerNextItemPagination', START...");
        console.log(`next num pagination is '${num}'`);

        if(this.state.currentNumPagination === num){
            return;
        }

        console.log(`send request to next pagination '${num}'`);

        this.props.socketIo.emit("get next chunk list tasks files not downloaded", {
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
                    active={this.state.currentNumPagination === i}
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

    getListNetworkParameters(type, item){
        let getListDirection = (d) => {
            if(item[d].length === 0){
                return { value: "", success: false };
            }

            let result = item[d].map((item) => {
                if(d === "src"){
                    return (<div className="ml-4" key={`elem_${type}_${d}_${item}`}>
                        <small>{item}</small>
                    </div>); 
                }
                if(d === "dst"){
                    return (<div className="ml-4" key={`elem_${type}_${d}_${item}`}>
                        <small>{item}</small>
                    </div>); 
                }

                return (<div className="ml-4" key={`elem_${type}_${d}_${item}`}>
                    <small>{item}</small>
                </div>); 
            });

            return { value: result, success: true };
        };

        let resultAny = getListDirection("any");
        let resultSrc = getListDirection("src");
        let resultDst = getListDirection("dst");

        return (
            <React.Fragment>
                {(resultAny.success) ? <div><small className="text-info">any&#8596; </small></div> : ""}
                <div className="text-left">{resultAny.value}</div>
                {(resultSrc.success) ? <div><small className="text-info">src&#8592; </small></div> : ""}
                <div className="text-left">{resultSrc.value}</div>
                {(resultDst.success) ? <div><small className="text-info">dst&#8594; </small></div> : ""}
                <div className="text-left">{resultDst.value}</div>
            </React.Fragment>
        );
    }

    createTableListDownloadFile(){
        let createTableBody = () => {
            if((typeof this.state.listFileDownloadOptions.slft === "undefined") || (this.state.listFileDownloadOptions.slft.length === 0)){
                return;
            }

            let num = 0;
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
                        <small>{this.getListNetworkParameters("ip", item.pf.f.ip)}</small>
                    </td>
                    <td className="my_line_spacing clicabe_cursor" onClick={this.headerClickTable.bind(this, dataInfo, "info")} key={`tr_${item.tid}_network`}>
                        <small>{this.getListNetworkParameters("nw", item.pf.f.nw)}</small>
                    </td>
                    <td className="my_line_spacing clicabe_cursor" onClick={this.headerClickTable.bind(this, dataInfo, "info")} key={`tr_${item.tid}_port`}>
                        <small>{this.getListNetworkParameters("pt", item.pf.f.pt)}</small>
                    </td>
                    <td className="align-middle clicabe_cursor" onClick={this.headerClickTable.bind(this, dataInfo, "info")} key={`tr_${item.tid}_search_file`}>
                        <small>{formaterInt.format(item.nffarf)}</small>
                    </td>
                    <td className="align-middle clicabe_cursor" onClick={this.headerClickTable.bind(this, dataInfo, "info")} key={`tr_${item.tid}_size_search_files`}>
                        <small>{`${formaterInt.format(item.tsffarf)} байт.`}</small>
                    </td>
                    <td className="align-middle clicabe_cursor" onClick={this.headerClickTable.bind(this, dataInfo, "info")} key={`tr_${item.tid}_download_files`}>
                        <small>{formaterInt.format(item.nfd)}</small>
                    </td>
                    <td className="align-middle" onClick={this.headerClickTable.bind(this, dataInfo, "download")}>
                        <OverlayTrigger
                            key={`tooltip_${item.tid}_download_img`}
                            placement="top"
                            overlay={<Tooltip>скачать файлы</Tooltip>}>
                            <a href="#" /*onClick={this.props.handlerTaskInfo.bind(this, item)}*/>
                                <img className="clickable_icon" src="./images/icons8-download-from-the-cloud-32.png" alt="скачать"></img>
                            </a>
                        </OverlayTrigger>
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
                                <th className="my_line_spacing">ID</th>
                                <th className="my_line_spacing">название</th>
                                <th className="my_line_spacing">интервал времени</th>
                                <th className="my_line_spacing">сет. протокол</th>
                                <th className="my_line_spacing">ip адреса</th>
                                <th>сети</th>
                                <th>порты</th>
                                <th className="my_line_spacing">найденные файлы</th>
                                <th className="my_line_spacing">общий размер найденных файлов</th>
                                <th className="my_line_spacing">загруженные файлы</th>
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
};