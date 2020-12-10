import React from "react";
import { Button, Badge, Card, Col, Form, Row } from "react-bootstrap";
import PropTypes from "prop-types";

/* 
 * Test
 * 
*/
export default class CreateBody extends React.Component {
    constructor(props){
        super(props);
        //this.dropZone = "";
        this.state = {    };

        this.handleDeleteElement = id => {
            this.setState(prevState => ({
                elements: prevState.elements.filter(el => el.id != id),
            }));
        };
        this.onDragOver = this.onDragOver.bind(this);

    }

    onDragOver (event){
            event.preventDefault();
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
                <div class='parent'>
                    <span id='draggableSpan'
                        draggable='true'
                        ondragstart={this.onDragOver.bind(this)}>
                    draggable
                    </span>
 
            <span ondragover={this.onDragOver.bind(this)}>
            dropzone
            </span>
            </div>
            </React.Fragment>
        );
    }
}

CreateBody.propTypes ={
    ss: PropTypes.func.isRequired,
    socketIo: PropTypes.object.isRequired,
   // listSourcesInformation: PropTypes.object.isRequired,
};