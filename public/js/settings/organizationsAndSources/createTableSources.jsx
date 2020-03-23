import React from "react";
import { Form, Table, Tooltip, OverlayTrigger } from "react-bootstrap";
import PropTypes from "prop-types";

export default class CreateTableSources extends React.Component {
    constructor(props){
        super(props);

        this.createTableBody = this.createTableBody.bind(this);
        this.showIconChangeInfo = this.showIconChangeInfo.bind(this);
    }

    showInfo(sourceID){
        this.props.handlerShowInfoWindow(sourceID);
    }

    showIconChangeInfo(sourceID){
        if(this.props.userPermissions.edit.status){
            return (
                <a href="#" onClick={this.props.handlerShowChangeInfo.bind(this, sourceID)}>
                    <img className="clickable_icon" src="./images/icons8-edit-16.png" alt="редактировать"></img>
                </a>
            );
        }

        return (<React.Fragment></React.Fragment>);
    }

    createTableBody() {
        /**
        {
                "sourceID": item.source_id,
                "sid": item.id,
                "shortName": item.short_name,
                "dateRegister": item.date_register,
                "fieldActivity": field,
                "versionApp": item.information_about_app.version,
                "releaseApp": item.information_about_app.date,
                "connectionStatus": false,
            };
         */

        console.log(this.props.tableSourceList);

        let sourcesID = Object.keys(this.props.listSourcesInformation);
        sourcesID.sort((a,b) => a>b);

        let listInfo = [];

        let num = 0;
        this.props.tableSourceList.forEach((elem) => {
            
            let status = (elem.connectionStatus) ? "my_circle_green":"my_circle_red";
            num++;

            listInfo.push(<tr key={`tr_${this.props.listSourcesInformation[sourceID].sid}`}>
                <td key={`td_${sourceID}_${this.props.listSourcesInformation[sourceID].sid}_status`} className="text-center">
                    <canvas className={status}></canvas>
                </td>                
                <td key={`td_${sourceID}_${this.props.listSourcesInformation[sourceID].sid}_source_id`} className="text-right">
                    <a href="#" onClick={this.showInfo.bind(this, sourceID)}>{sourceID}</a>
                </td>
                <td key={`td_${sourceID}_${this.props.listSourcesInformation[sourceID].sid}_short_name`} className="text-left">
                    {this.props.listSourcesInformation[sourceID].shortName}
                </td>
                <td key={`td_${sourceID}_${this.props.listSourcesInformation[sourceID].sid}_field_activity`} className="text-left">
                    {this.props.listSourcesInformation[sourceID].fieldActivity}
                </td>
                <td key={`td_${sourceID}_${this.props.listSourcesInformation[sourceID].sid}_date_register`} className="text-left">
                    {this.props.listSourcesInformation[sourceID].dateRegister}
                </td>
                <td key={`td_${sourceID}_${this.props.listSourcesInformation[sourceID].sid}_ver_app`} className="text-right">
                    {this.props.listSourcesInformation[sourceID].versionApp}
                </td>
                <td key={`td_${sourceID}_${this.props.listSourcesInformation[sourceID].sid}_rel_app`} className="text-center">
                    {this.props.listSourcesInformation[sourceID].releaseApp}
                </td>
                <td key={`td_${sourceID}_${this.props.listSourcesInformation[sourceID].sid}_change_info`}>
                    <OverlayTrigger
                        key={`tooltip_${this.props.listSourcesInformation[sourceID].sid}_img`}
                        placement="top"
                        overlay={<Tooltip>редактировать информацию</Tooltip>}>
                        {this.showIconChangeInfo(sourceID)}
                    </OverlayTrigger>
                </td>
                <td key={`td_${sourceID}_${this.props.listSourcesInformation[sourceID].sid}_checkbox`} className="text-right">              
                    <OverlayTrigger
                        key={`tooltip_${this.props.listSourcesInformation[sourceID].sid}_checkbox`}
                        placement="right"
                        overlay={<Tooltip>отметить для удаления</Tooltip>}>
                        <Form>
                            <Form.Check 
                                custom 
                                onChange={this.props.changeCheckboxMarked.bind(this, sourceID)}
                                type="checkbox" 
                                id={`checkbox-${sourceID}`}
                                label=""
                            />
                        </Form>
                    </OverlayTrigger>
                </td>
            </tr>);
        });
        /*sourcesID.forEach(sourceID => {
            
            let status = (2 < num && num < 5) ? "my_circle_red":"my_circle_green";
            num++;

            listInfo.push(<tr key={`tr_${this.props.listSourcesInformation[sourceID].sid}`}>
                <td key={`td_${sourceID}_${this.props.listSourcesInformation[sourceID].sid}_status`} className="text-center">
                    <canvas className={status}></canvas>
                </td>                
                <td key={`td_${sourceID}_${this.props.listSourcesInformation[sourceID].sid}_source_id`} className="text-right">
                    <a href="#" onClick={this.showInfo.bind(this, sourceID)}>{sourceID}</a>
                </td>
                <td key={`td_${sourceID}_${this.props.listSourcesInformation[sourceID].sid}_short_name`} className="text-left">
                    {this.props.listSourcesInformation[sourceID].shortName}
                </td>
                <td key={`td_${sourceID}_${this.props.listSourcesInformation[sourceID].sid}_field_activity`} className="text-left">
                    {this.props.listSourcesInformation[sourceID].fieldActivity}
                </td>
                <td key={`td_${sourceID}_${this.props.listSourcesInformation[sourceID].sid}_date_register`} className="text-left">
                    {this.props.listSourcesInformation[sourceID].dateRegister}
                </td>
                <td key={`td_${sourceID}_${this.props.listSourcesInformation[sourceID].sid}_ver_app`} className="text-right">
                    {this.props.listSourcesInformation[sourceID].versionApp}
                </td>
                <td key={`td_${sourceID}_${this.props.listSourcesInformation[sourceID].sid}_rel_app`} className="text-center">
                    {this.props.listSourcesInformation[sourceID].releaseApp}
                </td>
                <td key={`td_${sourceID}_${this.props.listSourcesInformation[sourceID].sid}_change_info`}>
                    <OverlayTrigger
                        key={`tooltip_${this.props.listSourcesInformation[sourceID].sid}_img`}
                        placement="top"
                        overlay={<Tooltip>редактировать информацию</Tooltip>}>
                        {this.showIconChangeInfo(sourceID)}
                    </OverlayTrigger>
                </td>
                <td key={`td_${sourceID}_${this.props.listSourcesInformation[sourceID].sid}_checkbox`} className="text-right">              
                    <OverlayTrigger
                        key={`tooltip_${this.props.listSourcesInformation[sourceID].sid}_checkbox`}
                        placement="right"
                        overlay={<Tooltip>отметить для удаления</Tooltip>}>
                        <Form>
                            <Form.Check 
                                custom 
                                onChange={this.props.changeCheckboxMarked.bind(this, sourceID)}
                                type="checkbox" 
                                id={`checkbox-${sourceID}`}
                                label=""
                            />
                        </Form>
                    </OverlayTrigger>
                </td>
            </tr>);
        });*/

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
    listSourcesInformation: PropTypes.object.isRequired,
};
