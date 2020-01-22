import React from "react";
import { Button, Tooltip, OverlayTrigger, Table } from "react-bootstrap";
import PropTypes from "prop-types";

export default class CreateTableDivision extends React.Component {
    constructor(props){
        super(props);

        this.createTableBody = this.createTableBody.bind(this);
    }

    createTableBody() {
        let listInfo = [];

        /**
<td key={`td_${item.id}_divisionName`} className="text-left">
                    {item.divisionName}
                </td>
                <td key={`td_${item.id}_organization`} className="text-left">
                    {item.organization}
                </td>
                <td key={`td_${item.id}_dateRegister`} className="text-left">
                    {item.dateRegister}
                </td>
                <td key={`td_${item.id}_countSources`} className="text-right">
                    {item.countSources}
                </td>
                <td key={`td_${item.id}_info`} className="text-right">
                    <Button variant="outline-secondary" size="sm">
                        <img src="./images/info-2x.png" alt="информация"></img>
                    </Button>
                </td>
 */

        let num = 0;
        this.props.listDivisionInformation.forEach(item => {
            let organization = (item.organization.length <= 28) ? item.organization: `${item.organization.substr(0, 25)}...`;

            listInfo.push(<tr key={`tr_${item.id}`}>
                <td key={`td_${item.id}_num`} className="text-center">
                    {++num}
                </td>
                <td key={`td_${item.id}_divisionName`} className="text-left">
                    {item.divisionName}
                </td>
                <td key={`td_${item.id}_organization`} className="text-left">
                    {organization}
                </td>
                <td key={`td_${item.id}_dateRegister`} className="text-center">
                    {item.dateRegister}
                </td>
                <td key={`td_${item.id}_countSources`} className="text-right">
                    {item.countSources}
                </td>
                <td key={`td_${item.id}_info`} className="text-right">
                    <Button variant="outline-secondary" size="sm">
                        <img src="./images/info-2x.png" alt="информация"></img>
                    </Button>
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
                        <th>№</th>
                        <th>Подразделение</th>
                        <th>Организация</th>
                        <th>Дата создания</th>
                        <th>Источников</th>
                        <th></th>
                    </tr>
                </thead>
                {this.createTableBody()}
            </Table>
        );
    }
}

/**
 *                     <tr>
                        <th>Подразделение</th>
                        <th>Организация</th>
                        <th>Дата создания</th>
                        <th>Источников</th>
                        <th></th>
                    </tr>
 */

CreateTableDivision.propTypes ={
    listDivisionInformation: PropTypes.array.isRequired,
};