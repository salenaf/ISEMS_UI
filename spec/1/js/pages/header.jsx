import React from "react";
import ReactDOM from "react-dom";
import { Button, Nav, Navbar } from "react-bootstrap";

class MyHeader extends React.Component {
    constructor(props){
        super(props);
    }

    render(){
        return (
            <Navbar bg="light" expand="lg">
                <Navbar.Brand href="/">
                    <img src="./images/logo.png" className="d-inline-block align-top" height="50" width="120" />
                </Navbar.Brand>
                <Navbar.Toggle aria-controls="responsive-navbar-nav" />
                
                <Nav className="mr-auto"></Nav>               
                
                <Navbar.Text>Иванов Петр Семенович</Navbar.Text>&nbsp;&nbsp;
                <Button variant="outline-primary" size="sm" href="logout">ВЫХОД</Button>
            </Navbar>);
    }
}

ReactDOM.render(<MyHeader />, document.getElementById("main-header"));