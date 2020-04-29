import React from "react";
import { Form, Table, Tooltip, OverlayTrigger } from "react-bootstrap";
import PropTypes from "prop-types";

export default class CreateTableSources extends React.Component {
    constructor(props){
        super(props);

        this.createTableBody = this.createTableBody.bind(this);
        this.showIconChangeInfo = this.showIconChangeInfo.bind(this);
        this.showIconSourceReconnect = this.showIconSourceReconnect.bind(this);
    }

    showInfo(sourceID){
        this.props.handlerShowInfoWindow(sourceID);
    }

    showIconChangeInfo(objInfo){
        if(this.props.userPermissions.management_sources.element_settings.edit.status){
            return (
                <a href="#" onClick={this.props.handlerShowChangeInfo.bind(this, objInfo)}>
                    <img className="clickable_icon" src="./images/icons8-edit-16.png" alt="редактировать"></img>
                </a>
            );
        }

        return (<React.Fragment></React.Fragment>);
    }

    showIconSourceReconnect(objInfo){
        return (
            <a href="#" onClick={this.props.handlerSourceReconnect.bind(this, objInfo)}>
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
        let listInfo = [];
        let num = 0;
        this.props.tableSourceList.forEach((elem) => {           
            let status = (elem.connectionStatus) ? "my_circle_green":"my_circle_red";
            num++;

            listInfo.push(<tr key={`tr_${elem.sid}`}>
                <td key={`td_${elem.sourceID}_${elem.sid}_status`} className="text-center">
                    <canvas className={status}></canvas>
                </td>                
                <td key={`td_${elem.sourceID}_${elem.sid}_source_id`} className="text-right">
                    <a href="#" onClick={this.showInfo.bind(this, {sid: elem.sid, sourceID: elem.sourceID})}>{elem.sourceID}</a>
                </td>
                <td key={`td_${elem.sourceID}_${elem.sid}_short_name`} className="text-left">
                    {elem.shortName}
                </td>
                <td key={`td_${elem.sourceID}_${elem.sid}_field_activity`} className="text-left">
                    {elem.fieldActivity}
                </td>
                <td key={`td_${elem.sourceID}_${elem.sid}_date_register`} className="text-left">
                    {formatter.format(elem.dateRegister)}
                </td>
                <td key={`td_${elem.sourceID}_${elem.sid}_ver_app`} className="text-right">
                    {elem.versionApp}
                </td>
                <td key={`td_${elem.sourceID}_${elem.sid}_rel_app`} className="text-center">
                    {elem.releaseApp}
                </td>
                <td key={`td_${elem.sourceID}_${elem.sid}_change_info`}>
                    <OverlayTrigger
                        key={`tooltip_${elem.sid}_img`}
                        placement="top"
                        overlay={<Tooltip>редактировать информацию</Tooltip>}>
                        {this.showIconChangeInfo({ sid: elem.sid, sourceID: elem.sourceID })}
                    </OverlayTrigger>
                </td>
                <td key={`td_${elem.sourceID}_${elem.sid}_recon_info`}>
                    <OverlayTrigger
                        key={`tooltip_${elem.sid}_img`}
                        placement="top"
                        overlay={<Tooltip>переподключить источник</Tooltip>}>
                        {this.showIconSourceReconnect({ sid: elem.sid, sourceID: elem.sourceID })}
                    </OverlayTrigger>
                </td>
                <td key={`td_${elem.sourceID}_${elem.sid}_checkbox`} className="text-right">              
                    <OverlayTrigger
                        key={`tooltip_${elem.sid}_checkbox`}
                        placement="right"
                        overlay={<Tooltip>отметить для удаления</Tooltip>}>
                        <Form>
                            <Form.Check 
                                custom 
                                onChange={this.props.changeCheckboxMarked.bind(this, elem.sourceID)}
                                type="checkbox" 
                                id={`checkbox-${elem.sourceID}`}
                                label="" />
                        </Form>
                    </OverlayTrigger>
                </td>
            </tr>);
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
