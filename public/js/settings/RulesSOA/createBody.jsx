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
        let strBody ="alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (  msg:\"Downloader.MediaDrug.HTTP.C&C\"; flow:established,to_server;  content:\"GET\"; http_method; content:\"advert_key=\"; http_uri; fast_pattern;   content:\"app=\"; http_uri;  content:\"oslang=\"; http_uri; classtype:trojan-activity; sid:35586741; rev:0;)";
  
        let pos1 = 0, pos2 = 0;
        pos1 = strBody.indexOf("classtype");
        pos2 = strBody.indexOf(";", pos1+1);
        let classTyp = strBody.slice(pos1 + 10 , pos2-1) ;
        console.log (`pos1 = ${pos1}; pos2 = ${pos2}; classType = ${classTyp}`);

    

        alert(classTyp);
    }
    
    funOut(){
        const { elements } = this.state;
        let outPutTabl = <React.Fragment>
            <table>
                <thead>
                    <tr>
                        <th> Название </th><th> Тип файла </th><th> Размер файла </th>
                    </tr>
                </thead>
                <tbody>
                    {elements.map(el => (
                        <tr key={el.id} >
                            <td> {el.name} </td> 
                            <td> {el.type} </td>
                            <td> {el.size} </td>
                            <td>  
                                <button type="button" className="close" onClick={() => { this.handleDeleteElement(el.id); }} aria-label="Close"> 
                                    <span aria-hidden="true">&times;</span>
                                </button> 
                            </td>  
                        </tr>
                    ))}
                </tbody>
                                
            </table>
                               
        </React.Fragment>;
        return outPutTabl;
    }

    render(){ 
       
        return (
            <React.Fragment>
                <label> что тута началось!</label>
                {this.funOut()}
                <button onClick={this.f.bind(this)}> Надоел! </button>
            </React.Fragment>
        );
    }
}

CreateBody.propTypes ={
    listSourcesInformation: PropTypes.object.isRequired,
};