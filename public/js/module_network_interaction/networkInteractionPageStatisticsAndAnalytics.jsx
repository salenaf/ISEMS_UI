import React from "react";
import ReactDOM from "react-dom";
import { Col, Row, OverlayTrigger, Tooltip, Table, Pagination } from "react-bootstrap";
import PropTypes from "prop-types";

import ListNetworkParameters from "../commons/listNetworkParameters.jsx";
import ModalWindowShowInformationTask from "../modal_windows/modalWindowShowInformationTask.jsx";


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
            currentTaskID: "",
        };

        this.userPermission=this.props.listItems.userPermissions;

        this.handlerEvents.call(this);

        this.sortElement = this.sortElement.bind(this);
        this.createTableListDownloadFile = this.createTableListDownloadFile.bind(this);
        this.handlerModalWindowShowTaskTnformation = this.handlerModalWindowShowTaskTnformation.bind(this);
        this.handlerShowModalWindowShowTaskInformation = this.handlerShowModalWindowShowTaskInformation.bind(this);
        this.handlerCloseModalWindowShowTaskInformation=this.handlerCloseModalWindowShowTaskInformation.bind(this);
    }

    /**
     * asc (по умолчанию) устанавливает порядок сортирования во возрастанию, от меньших значений к большим.
     * desc устанавливает порядок сортирования по убыванию, от больших значений к меньшим.
     */
    sortElement({ element = null, direction = "asc", list = null }){
        if(list === null){
            return [];
        }

        if(element === null){
            return list;
        }

        if(direction === "asc"){
            return list.sort((a,b) => a[element] - b[element]);
        } else {
            return list.sort((a,b) => b[element] - a[element]);
        }
    }

    handlerEvents(){
        this.props.socketIo.on("module NI API", (data) => {
            //для списка задач не отмеченных пользователем как завершеные
            if(data.type === "get list unresolved task"){
                if(data.options.tntf === 0){
                    return;
                }

                let tmpCopy = Object.assign(this.state.listTasksFound);
                tmpCopy = { 
                    p: data.options.p,
                    slft: this.sortElement({
                        element: "stte",
                        direction: "desc",
                        list: data.options.slft, 
                    }), 
                    tntf: data.options.tntf,
                };
                this.setState({ 
                    listTasksFound: tmpCopy,
                    currentTaskID: data.taskID,
                });
            }

            if(data.type === "send a list of found tasks"){
                
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
    }

    headerNextItemPagination(num){
        console.log("func 'headerNextItemPagination'");
        console.log(num);
        console.log(`taskID: ${this.state.shortTaskInformation.taskID}`);
        console.log(this.state.listTasksFound);

        if(this.state.listTasksFound.p.ccn === num){
            return;
        }

        /**
         * !!!!!!!!!!!!!
 * Сделать пагинатор на странице со списокм задач
 * по которым нужно выполнить анализ
 * Почему то прилетает информация преднозначенная для страницы поиска
 * 34 задачи в место 1 при переходе на цифру 2 пагинатора
 * 
 * 
 * ПОХОЖЕ мне нужен другой обработчик на свойство unresolvedTask
 * глобального объекта globalObject, а то с событием
 * "network interaction: get next chunk list all tasks" обращение
 * идет к свойству resultFoundTasks globalObject
 */

        this.props.socketIo.emit("network interaction: get next chunk list all tasks", {
            taskID: this.state.currentTaskID,
            chunkSize: this.state.listTasksFound.p.cs,
            nextChunk: num,
        });
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
                    <td className="align-middle clicabe_cursor" onClick={this.headerClickTable.bind(this, dataInfo, "info")} key={`tr_${item.tid}_date_create`}>
                        <small><i>{formatterDate.format(item.stte*1000)}</i></small>
                    </td>
                    <td className="align-middle clicabe_cursor text-info" onClick={this.headerClickTable.bind(this, dataInfo, "info")} key={`tr_${item.tid}_sourceID`}>
                        <small>{item.sid}</small>
                    </td>
                    <td className="align-middle my_line_spacing clicabe_cursor" onClick={this.headerClickTable.bind(this, dataInfo, "info")} key={`tr_${item.tid}_sourceName`}>
                        <small>{item.sn}</small>
                    </td>
                    <td className="align-middle my_line_spacing clicabe_cursor" onClick={this.headerClickTable.bind(this, dataInfo, "info")} key={`tr_${item.tid}_time`}>
                        <div><small><i>{formatterDate.format(item.pf.dt.s*1000)}</i></small></div>
                        <div><small><i>{formatterDate.format(item.pf.dt.e*1000)}</i></small></div>
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
                    <td className="align-middle" onClick={this.headerClickTable.bind(this, dataInfo, "processed")}>
                        <OverlayTrigger
                            key={"tooltip_forward_arrow_img"}
                            placement="bottom"
                            overlay={<Tooltip>{`анализ файлов, задача ID ${item.tid}`}</Tooltip>}>
                            <a href={`/network_interaction_page_statistics_and_analytics_detal_task?taskID=${item.tid}&sourceID=${item.sid}&sourceName=${item.sn}&taskBeginTime=${item.stte*1000}`}>
                                <img className="clickable_icon" width="24" height="24" src="../images/icons8-forward-button-48.png" alt="отметить как обработанную"></img>
                            </a>
                        </OverlayTrigger>
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
                                <th>время создания</th>
                                <th>sid</th>
                                <th>источник</th>
                                <th>интервал времени</th>
                                <th>ip</th>
                                <th>network</th>
                                <th>port</th>
                                <th>файлы найденны (выгружены)</th>
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
                <Row>
                    <Col md={12} className="text-right text-muted">
                        всего задач: <i>{this.state.listTasksFound.tntf}</i>
                    </Col>
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
