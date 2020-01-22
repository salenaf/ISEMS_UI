import React from "react";
import { Button, Form, Table } from "react-bootstrap";
import PropTypes from "prop-types";

export default class CreateTableSources extends React.Component {
    constructor(props){
        super(props);

        this.createTableBody = this.createTableBody.bind(this);
    }

    showInfo(sourceID){
        this.props.handlerShowInfoWindow(sourceID);
    }

    createTableBody() {
        let sourcesID = Object.keys(this.props.listSourcesInformation);
        sourcesID.sort((a,b) => a>b);

        let listInfo = [];

        let num = 0;
        sourcesID.forEach(sourceID => {
            
            let status = (2 < num && num < 5) ? "my_circle_red":"my_circle_green";
            num++;

            listInfo.push(<tr key={`tr_${this.props.listSourcesInformation[sourceID].id}`}>
                <td key={`td_${sourceID}_${this.props.listSourcesInformation[sourceID].id}_status`} className="text-center">
                    <canvas className={status}></canvas>
                </td>                
                <td key={`td_${sourceID}_${this.props.listSourcesInformation[sourceID].id}_source_id`} className="text-right">
                    <a href="#" onClick={this.showInfo.bind(this, sourceID)}>{sourceID}</a>
                </td>
                <td key={`td_${sourceID}_${this.props.listSourcesInformation[sourceID].id}_short_name`} className="text-left">
                    {this.props.listSourcesInformation[sourceID].shortName}
                </td>
                <td key={`td_${sourceID}_${this.props.listSourcesInformation[sourceID].id}_field_activity`} className="text-left">
                    {this.props.listSourcesInformation[sourceID].fieldActivity}
                </td>
                <td key={`td_${sourceID}_${this.props.listSourcesInformation[sourceID].id}_date_register`} className="text-left">
                    {this.props.listSourcesInformation[sourceID].dateRegister}
                </td>
                <td key={`td_${sourceID}_${this.props.listSourcesInformation[sourceID].id}_ver_app`} className="text-right">
                    {this.props.listSourcesInformation[sourceID].versionApp}
                </td>
                <td key={`td_${sourceID}_${this.props.listSourcesInformation[sourceID].id}_rel_app`} className="text-center">
                    {this.props.listSourcesInformation[sourceID].releaseApp}
                </td>
                <td key={`td_${sourceID}_${this.props.listSourcesInformation[sourceID].id}_checkbox`} className="text-right">
                    <Form>
                        <Form.Check 
                            custom 
                            onChange={this.props.changeCheckboxMarked.bind(this, sourceID)}
                            type="checkbox" 
                            id={`checkbox-${sourceID}`}
                            label=""
                        />
                    </Form>
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
                        <th>Статус</th>
                        <th>ID</th>
                        <th>Краткое название</th>
                        <th>Деятельность</th>
                        <th>Дата создания</th>
                        <th colSpan="2">Версия и дата ПО</th>
                        <th></th>
                    </tr>
                </thead>
                {this.createTableBody()}
            </Table>
        );
    }
}

CreateTableSources.propTypes ={
    changeCheckboxMarked: PropTypes.func.isRequired,
    handlerShowInfoWindow: PropTypes.func.isRequired,
    listSourcesInformation: PropTypes.object.isRequired,
};
