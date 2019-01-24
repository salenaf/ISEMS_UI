'use strict';

import React from 'react'
import ReactDOM from 'react-dom'

class ItemRow extends React.Component {
    constructor(props) {
        super(props)
    }

    render() {
        return (<li></li>)
    }
}

class CategoryRow extends React.Component {
    constructor(props) {
        super(props)
    }

    render() {
        return (<ul></ul>)
    }
}

class CreateLists extends React.Component {
    constructor(props) {
        super(props)
    }

    render() {
        return (<div></div>)
    }
}

class ButtonAddGroup extends React.Component {
    constructor(props) {
        super(props);
    }

    render() {
        let disabledCreate = (this.props.access.create.status) ? 'disabled' : '';

        return (
            <button type="button" className="btn btn-default btn-sm" id="buttonAddGroup" disabled={disabledCreate} >
                <span className="glyphicon glyphicon-plus"></span> добавить
            </button>
        )
    }
}

class ManagementGroup extends React.Component {
    constructor(props) {
        super(props)
    }

    render() {
        let newArr = [];

        let disabledEdit = (this.props.access.edit.status) ? 'disabled' : '';
        let disabledDelete = (this.props.access.delete.status) ? 'disabled' : '';

        let divStileHidden = {
            visibility: 'hidden'
        };

        for (let groupName in this.props.info) {
            let buttons = <button type="button" className="btn btn-default btn-sm" style={divStileHidden}>
                <span className="glyphicon glyphicon-floppy-saved"></span>
            </button>

            if (groupName.toLowerCase() !== 'administrator') {
                buttons = <div>
                    <button type="button" className="btn btn-default btn-sm" name="buttonDelGroup" disabled={disabledDelete}>
                        <span className="glyphicon glyphicon-trash"></span>
                    </button>
                    <button type="button" className="btn btn-default btn-sm" name="buttonEditGroup" disabled={disabledEdit}>
                        <span className="glyphicon glyphicon-floppy-saved"></span>
                    </button>
                </div>
            }

            let element = <th className="text-left" key={groupName} data-group-name={groupName}>
                {groupName}
                {buttons}
            </th>

            newArr.push(element);
        }

        return newArr;
    }
}

class CreateTable extends React.Component {
    constructor(props) {
        super(props);
    }

    render() {

        console.log(this.props.accessRights);

        let divStyleWidth = {
            width: '20%'
        }

        return (
            <div>
                <p>Test element!!!</p>
                <table className="table table-striped table-hover table-sm">
                    <caption className="h4 text-uppercase">управление группами</caption>
                    <thead>
                        <tr>
                            <th className="text-right" style={divStyleWidth}>
                                <ButtonAddGroup access={this.props.accessRights} />
                            </th>
                            <ManagementGroup info={this.props.mainInformation} access={this.props.accessRights} />
                        </tr>
                    </thead>
                </table>
            </div>
        );
    }
}

ReactDOM.render(<CreateTable mainInformation={receivedFromServerMain} accessRights={receivedFromServerAccess} />,
    document.getElementById('field_information'));

(function () { })();

/**

                <CreateLists mainData={this.props.mainInformation} />

<%
                for(let groupName in mainContentAdministrator){
                    let disabledEdit = (accessRights.edit[0] === false) ? 'disabled="disabled"' : '';
                    let disabledDelete = (accessRights.delete[0] === false) ? 'disabled="disabled"' : '';
                %>
                <th class="text-left" data-group-name="<%= groupName %>">
                    <%= groupName %>
                    <% if(groupName.toLowerCase() !== 'administrator'){ %>
                    <button type="button" class="btn btn-default btn-sm" name="buttonDelGroup" <%= disabledDelete %>>
                        <span class="glyphicon glyphicon-trash"></span>
                    </button>
                    <button type="button" class="btn btn-default btn-sm" name="buttonEditGroup"<%= disabledEdit %>>
                        <span class="glyphicon glyphicon-floppy-saved"></span>
                    </button>
                    <% } else { %>
                    <button type="button" class="btn btn-default btn-sm" style="visibility: hidden">
                        <span class="glyphicon glyphicon-floppy-saved"></span>
                    </button>
                    <% } %>
                </th>
                <% } %>
 */