import React from "react";
import ReactDOM from "react-dom";
import { Button, Navbar, Nav, NavDropdown, Container } from "react-bootstrap";
import PropTypes from "prop-types";

import { ModalWindowChangeAdminPasswd } from "./commons/modalWindowChangeAdminPasswd.jsx";

class CreateHeaderMenu extends React.Component {
    constructor(props){
        super(props);

        this.listItems = this.props.listItems;
        this.createMenu = this.createMenu(this);

        console.log(this.listItems);
    }

    createSubmenu(listDropDown){
        let list = [];

        for(let item in listDropDown){
            let linkElemIsDisabled = "";
            let classElemIsDisable = "";
            if ((typeof listDropDown[item].status !== "undefined") && (!listDropDown[item].status)) {
                linkElemIsDisabled = "true";
                classElemIsDisable = " disabled";
            }
        
            list.push(<NavDropdown.Item className={classElemIsDisable} href={item} key={`${item}_key`} aria-disabled={linkElemIsDisabled}>
                {listDropDown[item].name.toLowerCase()}
            </NavDropdown.Item>);
        }

        return list;
    }

    createMenu(){
        let list = [];
        list.push(<Nav.Link href="/" key="main_key">{"главная".toLowerCase()}</Nav.Link>);

        let linkElemIsDisabled = "";
        let classElemIsDisable = "";
        let menuSettings = this.listItems.menuSettings;
        
        for(let key in menuSettings){
            let submenuIsExist = (typeof menuSettings[key].submenu === "undefined");

            if ((typeof menuSettings[key].status !== "undefined") && (!menuSettings[key].status)) {
                linkElemIsDisabled = "true";
                classElemIsDisable = " disabled";
            }

            if (submenuIsExist) {
                list.push(<Nav.Link className={classElemIsDisable} href={key} key={`${key}_key`} aria-disabled={linkElemIsDisabled}>
                    {menuSettings[key].name.toLowerCase()}
                </Nav.Link>);

                continue;
            }

            list.push(
                <NavDropdown title={menuSettings[key].name.toLowerCase()} key={`${key}_key`}>
                    {this.createSubmenu.call(this, menuSettings[key].submenu)}
                </NavDropdown>);
        }

        return list;
    }

    render(){
        return (
            <Container>
                <Navbar fixed="top" bg="light" variant="light">
                    <Navbar.Brand href="/">
                        <img src="images/logo.png" className="d-inline-block align-top" height="50" width="120" />
                    </Navbar.Brand>
                    <Navbar.Toggle aria-controls="basic-navbar-nav" />
                    <Nav className="mr-auto">{this.createMenu}</Nav>
                    <Navbar.Collapse className="justify-content-end">
                        <Navbar.Text>{this.listItems.userName}</Navbar.Text>&nbsp;&nbsp;
                        <Button variant="outline-primary" size="sm" href="logout">ВЫХОД</Button>
                    </Navbar.Collapse>
                </Navbar>
                <ModalWindowChangeAdminPasswd 
                    login={this.listItems.login} 
                    passIsDefault={this.listItems.isPasswordDefaultAdministrator}
                    socketIo={this.props.socketIo}/>
            </Container>);
    }
}

CreateHeaderMenu.protoType = {
    socketIo: PropTypes.object.isRequired,
    listItems: PropTypes.object.isRequired,
};

ReactDOM.render(<CreateHeaderMenu 
    listItems={resivedFromServer} 
    socketIo={socket} />, document.getElementById("menu-top"));
