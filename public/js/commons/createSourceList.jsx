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
            let isDisabled = false;
            if(this.props.swithCheckConnectionStatus){
                isDisabled = !(this.props.listSources[sourceID].connectStatus);          
            }

            return (
                <option 
                    key={`key_source_${num}_${this.props.listSources[sourceID].id}`} 
                    value={sourceID} 
                    disabled={isDisabled} >
                    {`${sourceID} ${this.props.listSources[sourceID].shortName}`}
                </option>
            );
        });
    }

    render(){
        let disabled = false;
        if(this.props.typeModal === "повторная"){
            if(this.props.hiddenFields){
                disabled = true;
            } else {              
                disabled = false;
            }
        }

        console.log("create list sources");
        console.log(`chosen item: '${this.props.currentSource}'`);

        return (
            <Form.Group>
                <Form.Control 
                    as="select" 
                    size="sm" 
                    disabled={disabled} 
                    onChange={this.props.handlerChosen} 
                    defaultValue={this.props.currentSource} 
                    id="dropdown_list_sources" >
                    <option key="key_source_0_0" value={0}></option>
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
    swithCheckConnectionStatus: PropTypes.bool.isRequired,
};