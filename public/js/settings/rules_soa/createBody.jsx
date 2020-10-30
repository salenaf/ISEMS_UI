import React from "react";
import { Button, Badge, Card, Col, Form, Row } from "react-bootstrap";
import PropTypes from "prop-types";


export default class CreateBody extends React.Component {
    constructor(props){
        super(props);
        //this.dropZone = "";
        this.state = {
            elements: [
                {
                    id: 1,
                    name: "First",
                    type: ".js",  
                    size: "3421",
                },
                {
                    id: 2,
                    name: "Second",
                    type: ".js4",
                    size: "3467",               
                },
                {
                    id: 3,
                    name: "Second1",
                    type: ".js3",
                    size: "32234",                  
                },
                {
                    id: 4,
                    name: "Second2",
                    type: ".js2",
                    size: "3445",  
                },
                {
                    id: 5,
                    name: "Second3",
                    type: ".js1",
                    size: "3243", 
                },
            ],
        };

        this.handleDeleteElement = id => {
            this.setState(prevState => ({
                elements: prevState.elements.filter(el => el.id != id),
            }));
        };
        this.funOut = this.funOut.bind(this);
        this.f      = this.f.bind(this);
    }

    
    f(){

    }
    
    funOut(){
        //const { elements } = this.state;
        let outPutTabl = <React.Fragment>
            
                               
        </React.Fragment>;
        return outPutTabl;
    }

    render(){ 
       
        return (
            <React.Fragment>
                
            </React.Fragment>
        );
    }
}

CreateBody.propTypes ={
    ss: PropTypes.func.isRequired,
    socketIo: PropTypes.object.isRequired,
    listSourcesInformation: PropTypes.object.isRequired,
};