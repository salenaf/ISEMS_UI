import React from "react";
import ReactDOM from "react-dom";
import { Button, Container, Navbar, Nav, NavDropdown, Tooltip, OverlayTrigger } from "react-bootstrap";
import PropTypes from "prop-types";

import { ModalWindowChangeAdminPasswd } from "./commons/modalWindowChangeAdminPasswd.jsx";

class CreateHeaderMenu extends React.Component {
    constructor(props){
        super(props);

        this.listItems = this.props.listItems;

        this.state = {
            "connectionModuleNI": this.connModuleNI.call(this),
        };

        this.createMenu = this.createMenu.bind(this);
        this.firstIconIsBig = this.firstIconIsBig.bind(this);
        this.statusConnectModules = this.statusConnectModules.bind(this);

        this.handlerEvents.call(this);
    }

    connModuleNI(){
        return (typeof this.listItems !== "undefined") ? this.listItems.connectionModules.moduleNI: false;
    }

    handlerEvents(){
        this.props.socketIo.on("module NI API", (data) => {
            if(data.type === "connectModuleNI"){
                if(data.options.connectionStatus){
                    this.setState({ "connectionModuleNI": true });
                } else {
                    this.setState({ "connectionModuleNI": false });
                }
            }
        });
    }

    statusConnectModules(){
        let imgIcon = (this.state.connectionModuleNI) ? "network_green.png" : "network_red.png";
        
        return (
            <OverlayTrigger
                placement="bottom"
                overlay={<Tooltip>модуль сетевого взаимодействия</Tooltip>}>
                <img src={"/images/"+imgIcon} width="30" height="30"/>
            </OverlayTrigger>
        );
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
        
            /**
 *      !!!!!!!!!
 * Временно выключаем доступ к некоторым пунктам
 * подменю
 *      !!!!!!!!!
 */

            if(item === "setting_geoip" || item === "setting_search_rules" || item === "setting_reputational_lists"){
                linkElemIsDisabled = "true";
                classElemIsDisable = " disabled";
            }

            list.push((<NavDropdown.Item 
                className={classElemIsDisable} 
                href={item} 
                key={`${item}_key`} 
                aria-disabled={linkElemIsDisabled}>
                {listDropDown[item].name.toLowerCase()}
            </NavDropdown.Item>));
        }

        return list;
    }

    firstIconIsBig(str) {
        if (!str) return str;
      
        return str[0].toUpperCase() + str.slice(1);
    }
    
    createMenu(){
        let list = [];
        list.push(<Nav.Link href="/" key="main_key">Главная</Nav.Link>);

        let linkElemIsDisabled = "";
        let classElemIsDisable = "";
        let menuSettings = this.listItems.menuSettings;
        
        for(let key in menuSettings){
            let submenuIsNotExist = (typeof menuSettings[key].submenu === "undefined");

            if ((typeof menuSettings[key].status !== "undefined") && (!menuSettings[key].status)) {
                linkElemIsDisabled = "true";
                classElemIsDisable = " disabled";
            }

            if (submenuIsNotExist) {
                /**
                *       !!!!!!!!!!!
                * временно выключаю доступ к некоторым элементам меню
                *       !!!!!!!!!!!
                */
                if(key === "analysis_sip" || key === "security_event_management"){
                    linkElemIsDisabled = "true";
                    classElemIsDisable = " disabled";
                }

                list.push(<Nav.Link className={classElemIsDisable} href={key} key={`${key}_key`} aria-disabled={linkElemIsDisabled}>
                    {this.firstIconIsBig(menuSettings[key].name)}
                </Nav.Link>);

                linkElemIsDisabled = "";
                classElemIsDisable = "";

                continue;
            }

            list.push(<NavDropdown title={this.firstIconIsBig(menuSettings[key].name)} key={`${key}_key`}>
                {this.createSubmenu.call(this, menuSettings[key].submenu)}
            </NavDropdown>);
        }

        return list;
    }

    render(){
        return (
            <Container>
                <Navbar bg="dark" variant="dark" fixed="top">
                    <Navbar.Brand href="/">
                        <img src="/images/logo1.png" width="200" height="60"/>
                    </Navbar.Brand>
                    <Navbar.Toggle aria-controls="basic-navbar-nav" />
                    <Nav className="mr-auto">{this.createMenu()}</Nav>
                    <Navbar.Collapse className="justify-content-end">
                        {this.statusConnectModules()}
                        &nbsp;&nbsp;
                        <Navbar.Text>{this.listItems.userName}</Navbar.Text>
                        &nbsp;&nbsp;
                        <Button variant="outline-info" size="sm" href="logout">ВЫХОД</Button>
                    </Navbar.Collapse>
                </Navbar>

                <ModalWindowChangeAdminPasswd 
                    login={this.listItems.login} 
                    passIsDefault={this.listItems.isPasswordDefaultAdministrator}
                    socketIo={this.props.socketIo}/>
            </Container>);
    }
}

CreateHeaderMenu.protoTypes = {
    socketIo: PropTypes.object.isRequired,
    listItems: PropTypes.object.isRequired,
};

ReactDOM.render(<CreateHeaderMenu 
    socketIo={socket}
    listItems={resivedFromServer} />, document.getElementById("menu-top"));
