import React from "react";
import { Form } from "react-bootstrap";
import PropTypes from "prop-types";


export default class CreateBodyManagementEntity extends React.Component {
    constructor(props){
        super(props);
    }

    render(){
        return (
            <React.Fragment>
                <br/>
                <Form.Control as="select" className="custom-select" size="sm">
                    <option key={1} value="0">Choose...</option>
                    <option key="int" disabled>NUMBERS</option>
                    <option key={2} value="1">One</option>
                    <option key={3} value="2">Ones</option>
                    <option key={4} value="3">One again</option>
                    <option key="text" disabled>TEXT</option>                    
                    <option key={5} value="4">Two</option>
                    <option key={6} value="5">Two again</option>
                    <option key={7} value="6">Three</option>
                </Form.Control>
            </React.Fragment>
        );
    }
}

CreateBodyManagementEntity.propTypes ={
//    changeCheckboxMarked: PropTypes.func.isRequired,
};

