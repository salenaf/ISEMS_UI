import React from "react";
import ReactDOM from "react-dom";
import { Button, Navbar, Nav, NavDropdown, Form, FormControl, Container } from "react-bootstrap";
//import PropTypes from "prop-types";

class CreateHeaderMenu extends React.Component {
    constructor(props){
        super(props);
    }

    render(){
        return (
            <Navbar bg="dark" variant="dark" fixed="top">
                <Navbar.Brand href="/">
                    <img src="./images/logo1.png" width="200" height="60"/>
                </Navbar.Brand>
                <Navbar.Toggle aria-controls="responsive-navbar-nav" />
                <Nav className="mr-auto">
                    <Nav.Item>
                        <Nav.Link href="/">Главная</Nav.Link>
                    </Nav.Item>
                    <Nav.Item>
                        <Nav.Link href="/">Аналитика</Nav.Link>
                    </Nav.Item>
                    <Nav.Item>
                        <Nav.Link href="/">Фильтрация</Nav.Link>
                    </Nav.Item>
                    <Nav.Item>
                        <Nav.Link href="/">Учет воздействий</Nav.Link>
                    </Nav.Item>
                    <Nav.Item>
                        <NavDropdown title="Настройки" id="nav-dropdown">
                            <NavDropdown.Item href="#action/3.2">пользователи</NavDropdown.Item>
                            <NavDropdown.Item href="#action/3.3">группы пользователей</NavDropdown.Item>
                            <NavDropdown.Divider />
                            <NavDropdown.Item href="#action/3.4">организации и источники</NavDropdown.Item>
                            <NavDropdown.Item href="#action/3.4">правила СОА</NavDropdown.Item>
                        </NavDropdown>
                    </Nav.Item>
                </Nav>
                <Navbar.Text>Иванов Петр Семенович</Navbar.Text>&nbsp;&nbsp;
                <Button variant="outline-info" size="sm" href="logout">ВЫХОД</Button>
            </Navbar>
        );
    }
}

/**
<Nav className="justify-content-center">
                <Nav.Item>
                    <Nav.Link href="/">Главная</Nav.Link>
                </Nav.Item>
                <Nav.Item>
                    <Nav.Link href="/">Аналитика</Nav.Link>
                </Nav.Item>
                <Nav.Item>
                    <Nav.Link href="/">Фильтрация</Nav.Link>
                </Nav.Item>
                <Nav.Item>
                    <Nav.Link href="/">Учет воздействий</Nav.Link>
                </Nav.Item>
                <Nav.Item>
                    <NavDropdown title="Настройки" id="nav-dropdown">
                        <NavDropdown.Item href="#action/3.2">пользователи</NavDropdown.Item>
                        <NavDropdown.Item href="#action/3.3">группы пользователей</NavDropdown.Item>
                        <NavDropdown.Divider />
                        <NavDropdown.Item href="#action/3.4">организации и источники</NavDropdown.Item>
                        <NavDropdown.Item href="#action/3.4">правила СОА</NavDropdown.Item>
                    </NavDropdown>
                </Nav.Item>
            </Nav>
 */

//CreateHeaderMenu.protoType = {};

ReactDOM.render(<CreateHeaderMenu />, document.getElementById("menu-top"));

/**
 *             <Navbar className="text-center" bg="light" expand="lg">
                <Nav>
                    <Nav.Link href="/">главная</Nav.Link>
                    <Nav.Link href="/">аналитика</Nav.Link>
                    <Nav.Link href="/">фильтрация</Nav.Link>
                    <Nav.Link href="/">учет воздействий</Nav.Link>
                    <NavDropdown title="модули" id="basic-nav-dropdown">
                        <NavDropdown.Item href="#action/3.2">сетевое взаимодействие</NavDropdown.Item>
                        <NavDropdown.Item href="#action/3.3">учет компьютерных воздействий</NavDropdown.Item>
                        <NavDropdown.Item href="#action/3.4">аналитическая обработка</NavDropdown.Item>
                    </NavDropdown>
                    <NavDropdown title="настройки" id="basic-nav-dropdown">
                        <NavDropdown.Item href="#action/3.2">пользователи</NavDropdown.Item>
                        <NavDropdown.Item href="#action/3.3">группы пользователей</NavDropdown.Item>
                        <NavDropdown.Divider />
                        <NavDropdown.Item href="#action/3.4">организации и источники</NavDropdown.Item>
                        <NavDropdown.Item href="#action/3.4">правила СОА</NavDropdown.Item>
                    </NavDropdown>
                </Nav>
            </Navbar>
 */