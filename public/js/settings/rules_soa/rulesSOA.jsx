import React from "react";
import ReactDOM from "react-dom";
//import { Button } from "react-bootstrap";
import PropTypes from "prop-types";

import CreateBodyAddFile from "./createBodyAddFile.jsx";
import CreateBodySearchSid  from "./createBodySearchSid.jsx";
import CreateBody  from "./createBody.jsx";
import { data } from "jquery";

//import { helpers } from "../../../common_helpers/helpers.js";

class CreatePageRulesSOASourse extends React.Component {
    constructor(props){
        super(props);

        this.state = {
            "listShortEntity": this.props.listShortEntity,
            disable :{
                str: "disabled",
                bool: "true"
            },

        };

        // this.shortListRuleSOA = this.shortListRuleSOA.bind(this);
        
        //this. handleFileSelect = this. handleFileSelect.bind(this);
        //устанавливаем тему для всех элементов select2
        //  $.fn.select2.defaults.set("theme", "bootstrap");

        this.hundlerEvents.call(this);
    }
    
    hundlerEvents(searchType, value){
        
        console.log("function 'hundlerEevents'");
        
        if(searchType === "sid"){
            let valueInPut = Number(value);

            console.log(`SID: ${valueInPut}`);
    
            //this.props.socketIo.emit("sid_bd: find-sid", { sid: valueInPut });
        }
        
        this.props.socketIo.on("rules soa", (data) => {
            this.setState({ listShortEntity: data.arguments });

            console.log(data.arguments);
        });

        this.props.socketIo.on("file upload result", (data) => {
            console.log(data);
        });
    }
    /**/
    render(){
        // console.log("=====> userPermissions");
        // console.log( this.props.userPermissionsSearch);
        if(this.props.userPermissions.create.status){
            this.state.disable = {
                str: "",
                bool: "false"
            };
        }
        return (
            <React.Fragment>
                <nav>
                    <div className="nav nav-tabs" id="nav-tab" role="tablist">
                        <a className="nav-item nav-link active" id="nav-home-tab" data-toggle="tab" href="#searchSid" role="tab" aria-controls="nav-home" aria-selected="true">Поиск по sid</a>
                        <a className={`nav-item nav-link ${this.state.disable.str}`} id="nav-profile-tab" data-toggle="tab" href="#addSid" role="tab" aria-controls="nav-profile" aria-selected="false" aria-disabled={`${this.state.disable.bool}`}>Загрузить sid из файлов</a>
                        {/*<a className="nav-item nav-link" id="nav-body-tab"    data-toggle="tab" href="#primer" role="tab" aria-controls="nav-profile" aria-selected="false">Пример</a>*/} 
                    </div>
                </nav>
           
           
                <div className="tab-content" id="nav-tabContent">
                    <br/> 
                    <div className="tab-pane fade show active" id="searchSid" role="tabpanel" aria-labelledby="nav-home-tab">
                        <CreateBodySearchSid 
                            socketIo={this.props.socketIo} 
                            listShortEntity={this.props.listShortEntity}                            
                            userPermissions={this.props.userPermissions}
                            />
                    </div>
                    <div className="tab-pane fade" id="addSid" role="tabpanel" aria-labelledby="nav-profile-tab">
                        <CreateBodyAddFile   
                            ss={this.props.ss} 
                            socketIo={this.props.socketIo} 
                            userPermissions= {this.props.userPermissions}/>
                    </div>  
                    <div className="tab-pane fade" id="primer" role="tabpanel" aria-labelledby="nav-body-tab">
                        <CreateBody 
                            ss={this.props.ss} 
                            socketIo={this.props.socketIo}/>
                    </div> 
                </div>
            </React.Fragment>
        );
    }
}

CreatePageRulesSOASourse.propTypes ={
    ss: PropTypes.func.isRequired,
    socketIo:PropTypes.object.isRequired,
    listShortEntity: PropTypes.object.isRequired,
   // userPermissionsSearch: PropTypes.object.isRequired,
    userPermissions: PropTypes.object.isRequired,
};


ReactDOM.render(<CreatePageRulesSOASourse 
    ss={ss}
    socketIo={socket}
    listShortEntity={receivedFromServerMain}
    userPermissions = {receivedFromServerAccess}/>, document.getElementById("page-rules-soa"));

