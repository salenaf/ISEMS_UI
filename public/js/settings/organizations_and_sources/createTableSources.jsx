import React from "react";
import { Form, Table } from "react-bootstrap";
import PropTypes from "prop-types";

export default class CreateTableSources extends React.Component {
    constructor(props){
        super(props);

        this.createTableBody = this.createTableBody.bind(this);
        this.showIconChangeInfo = this.showIconChangeInfo.bind(this);
        this.showIconSourceReconnect = this.showIconSourceReconnect.bind(this);
    }

    componentDidUpdate(){
        $("[value='source_reconnect']").tooltip();
        $("[value='edit_source']").tooltip();
    }

    showInfo(sourceID){
        this.props.handlerShowInfoWindow(sourceID);
    }

    showIconChangeInfo(objInfo){
        if(this.props.userPermissions.management_sources.element_settings.edit.status){
            return (
                <a 
                    href="#" 
                    value="edit_source"
                    data-toggle="tooltip" 
                    data-placement="top" 
                    title="редактировать информацию" 
                    onClick={this.props.handlerShowChangeInfo.bind(this, objInfo)}>
                    <img className="clickable_icon" src="./images/icons8-edit-16.png" alt="редактировать"></img>
                </a>
            );
        }

        return (<React.Fragment></React.Fragment>);
    }

    showIconSourceReconnect(objInfo){
        return (
            <a 
                href="#" 
                value="source_reconnect"
                data-toggle="tooltip" 
                data-placement="top" 
                title="переподключить источник" 
                onClick={this.props.handlerSourceReconnect.bind(this, objInfo)}>
                <img className="clickable_icon" src="./images/icons8-refresh-16.png" alt="переподключить"></img>
            </a>
        );
    }

    createTableBody() {
        let formatter = Intl.DateTimeFormat("ru-Ru", {
            timeZone: "Europe/Moscow",
            day: "numeric",
            month: "numeric",
            year: "numeric",
            hour: "numeric",
            minute: "numeric",
        });

        //получаем номер самой свежей версии хостового приложения
        let listTmp = [];
        for(let item in this.props.tableSourceList){
            if(this.props.tableSourceList[item].versionApp === ""){
                continue;
            }

            if(typeof this.props.tableSourceList[item].versionApp === "undefined"){
                continue;
            }

            let int = parseInt(this.props.tableSourceList[item].versionApp.replace(/[^\d]/g, ""));

            if(!isFinite(int)){
                continue;
            }

            listTmp.push(int);
        }

        listTmp.sort();
        listTmp.reverse();

        let maxValue = (listTmp.length > 0) ? listTmp[0] : 0; 
        let listInfo = [];
        let num = 0;
        this.props.tableSourceList.forEach((elem) => {           
            let status = (elem.connectionStatus) ? "my_circle_green":"my_circle_red";
            num++;

            let warningAppVersion = (parseInt(elem.versionApp.replace(/[^\d]/g, "")) < maxValue) ? "text-danger": "";

            if(elem.sid.length === 0){
                listInfo.push(<tr key={`tr_${num}_${elem.sid}`} className="text-muted">
                    <td key={`td_${elem.sourceID}_${elem.sid}_status`} className="text-center">
                        <canvas className={status}></canvas>
                    </td>                
                    <td key={`td_${elem.sourceID}_${elem.sid}_source_id`} className="text-right">
                        {elem.sourceID}
                    </td>
                    <td key={`td_${elem.sourceID}_${elem.sid}_short_name`} className="text-left">
                        {elem.shortName}
                    </td>
                    <td colSpan={4} key={`td_${elem.sourceID}_${elem.sid}_info`} className="text-center text-danger">
                        <small>сторонний источник, добавлен другим UI, взаимодействие ограниченно</small>
                    </td>
                    <td key={`td_${elem.sourceID}_${elem.sid}_change_info`}></td>
                    <td key={`td_${elem.sourceID}_${elem.sid}_recon_info`}>
                        {this.showIconSourceReconnect({ sid: elem.sid, sourceID: elem.sourceID })}
                    </td>
                    <td key={`td_${elem.sourceID}_${elem.sid}_checkbox`} className="text-right"></td>
                </tr>);
            } else {
                listInfo.push(<tr key={`tr_${num}_${elem.sid}`} className="text-muted">
                    <td key={`td_${elem.sourceID}_${elem.sid}_status`} className="text-center">
                        <canvas className={status}></canvas>
                    </td>                
                    <td 
                        key={`td_${elem.sourceID}_${elem.sid}_source_id`} 
                        className="text-right text-info clicabe_cursor"
                        onClick={this.showInfo.bind(this, {sid: elem.sid, sourceID: elem.sourceID})} >
                        {elem.sourceID}
                    </td>
                    <td key={`td_${elem.sourceID}_${elem.sid}_short_name`} className="text-left clicabe_cursor" onClick={this.showInfo.bind(this, {sid: elem.sid, sourceID: elem.sourceID})}>
                        {elem.shortName}
                    </td>
                    <td key={`td_${elem.sourceID}_${elem.sid}_field_activity`} className="text-left clicabe_cursor" onClick={this.showInfo.bind(this, {sid: elem.sid, sourceID: elem.sourceID})}>
                        {elem.fieldActivity}
                    </td>
                    <td key={`td_${elem.sourceID}_${elem.sid}_date_register`} className="text-left clicabe_cursor" onClick={this.showInfo.bind(this, {sid: elem.sid, sourceID: elem.sourceID})}>
                        {formatter.format(elem.dateRegister)}
                    </td>
                    <td key={`td_${elem.sourceID}_${elem.sid}_ver_app`} className="text-right clicabe_cursor" onClick={this.showInfo.bind(this, {sid: elem.sid, sourceID: elem.sourceID})}>
                        <span className={warningAppVersion}>{elem.versionApp}</span>
                    </td>
                    <td key={`td_${elem.sourceID}_${elem.sid}_rel_app`} className="text-center clicabe_cursor" onClick={this.showInfo.bind(this, {sid: elem.sid, sourceID: elem.sourceID})}>
                        {elem.releaseApp}
                    </td>
                    <td key={`td_${elem.sourceID}_${elem.sid}_change_info`}>
                        {this.showIconChangeInfo({ sid: elem.sid, sourceID: elem.sourceID })}
                    </td>
                    <td key={`td_${elem.sourceID}_${elem.sid}_recon_info`}>
                        {this.showIconSourceReconnect({ sid: elem.sid, sourceID: elem.sourceID })}
                    </td>
                    <td key={`td_${elem.sourceID}_${elem.sid}_checkbox`} className="text-right">              
                        <Form>
                            <Form.Check 
                                className="mt-1"
                                custom 
                                onChange={this.props.changeCheckboxMarked.bind(this, elem.sourceID)}
                                type="checkbox" 
                                id={`checkbox-${elem.sourceID}`}
                                label="" />
                        </Form>
                    </td>
                </tr>);
            }
        });

        return (
            <tbody>{listInfo}</tbody>
        );
    }

    render() {
        return (
            <Table size="sm" striped hover>
                <thead>
                    <tr>
                        <th></th>
                        <th>ID</th>
                        <th>Краткое название</th>
                        <th>Деятельность</th>
                        <th>Дата создания</th>
                        <th colSpan="2">Версия и дата ПО</th>
                        <th></th>
                        <th></th>
                        <th></th>
                    </tr>
                </thead>
                {this.createTableBody()}
            </Table>
        );
    }
}

CreateTableSources.propTypes ={
    userPermissions: PropTypes.object.isRequired,
    tableSourceList: PropTypes.array.isRequired,
    changeCheckboxMarked: PropTypes.func.isRequired,
    handlerShowInfoWindow: PropTypes.func.isRequired,
    handlerShowChangeInfo: PropTypes.func.isRequired,
    handlerSourceReconnect: PropTypes.func.isRequired,
};
