"use strict";

import React from "react";
import { Form } from "react-bootstrap";
import PropTypes from "prop-types";

export default class CreateSourceList extends React.Component {
    constructor(props){
        super(props);

        this.getListSource = this.getListSource.bind(this);
    }

    getListSource(){
        return Object.keys(this.props.listSources).sort((a, b) => a < b).map((sourceID, num) => {
            let isDisabled = !(this.props.listSources[sourceID].connectStatus);          

            return (
                <option 
                    key={`key_source_${num}_${this.props.listSources[sourceID].id}`} 
                    value={sourceID} 
                >
                    {`${sourceID} ${this.props.listSources[sourceID].shortName}`}
                </option>
            );
        });
    }

    /** 
     *          ВНИМАНИЕ!!!
     * убираем  disabled={isDisabled} из options ТОЛЬКО ДЛЯ ТЕСТОВ 
     * */

    render(){
        let disabled = false;
        if(this.props.typeModal === "повторная"){
            if(this.props.hiddenFields){
                disabled = true;
            } else {              
                disabled = false;
            }
        }

        return (
            <Form.Group>
                <Form.Control 
                    disabled={disabled} 
                    onChange={this.props.handlerChosen} 
                    defaultValue={this.props.currentSource} 
                    as="select" 
                    size="sm" 
                    id="dropdown_list_sources" >
                    <option></option>
                    {this.getListSource()}
                </Form.Control>
            </Form.Group>
        );
    }
}

CreateSourceList.propTypes = {
    typeModal: PropTypes.string.isRequired,
    hiddenFields: PropTypes.bool.isRequired,
    listSources: PropTypes.object.isRequired,
    currentSource: PropTypes.number.isRequired,
    handlerChosen: PropTypes.func.isRequired,
};