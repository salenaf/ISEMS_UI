import React from "react";
import ReactDOM from "react-dom";
//import { Button } from "react-bootstrap";
import PropTypes from "prop-types";

import CreateBodyAddFile from "./createBodyAddFile.jsx";
import CreateBodySearchSid  from "./createBodySearchSid.jsx";
import CreateBody  from "./createBody.jsx";
//import { helpers } from "../../../common_helpers/helpers.js";

class CreatePageRulesSOASourse extends React.Component {
    constructor(props){
        super(props);

        //this. handleFileSelect = this. handleFileSelect.bind(this);
        //устанавливаем тему для всех элементов select2
        //  $.fn.select2.defaults.set("theme", "bootstrap");
    }
    


    render(){
        //let text = "Файл не выбран";

        //let n=5;
        // Setup the dnd listeners.
        //let dropZone= this.document.getElementById("drop_zone") ;
        return (
            <React.Fragment>
                <nav>
                    <div className="nav nav-tabs" id="nav-tab" role="tablist">
                        <a className="nav-item nav-link active" id="nav-home-tab" data-toggle="tab" href="#searchSid" role="tab" aria-controls="nav-home" aria-selected="true">Поиск по sid</a>
                        <a className="nav-item nav-link" id="nav-profile-tab" data-toggle="tab" href="#addSid" role="tab" aria-controls="nav-profile" aria-selected="false">Открыть файл</a>
                        <a className="nav-item nav-link" id="nav-body-tab"    data-toggle="tab" href="#primer" role="tab" aria-controls="nav-profile" aria-selected="false">Пример</a>
                    </div>
                </nav>
           
                <div className="tab-content" id="nav-tabContent">
                    <br/> 
                    <div className="tab-pane fade show active" id="searchSid" role="tabpanel" aria-labelledby="nav-home-tab">
                        <CreateBodySearchSid socketIo={this.props.socketIo} listSourcesInformation={this.props.listSourcesInformation}/>
                    </div>
                    <div className="tab-pane fade" id="addSid" role="tabpanel" aria-labelledby="nav-profile-tab">
                        <CreateBodyAddFile   ss={this.props.ss} socketIo={this.props.socketIo} listSourcesInformation={this.props.listSourcesInformation}/>
                    </div>  
                    <div className="tab-pane fade" id="primer" role="tabpanel" aria-labelledby="nav-body-tab">
                        <CreateBody           listSourcesInformation={this.props.listSourcesInformation}/>
                    </div> 
                </div>
            </React.Fragment>
        );
    }
}

CreatePageRulesSOASourse .propTypes ={
    ss: PropTypes.func.isRequired,
    socketIo:PropTypes.object.isRequired,
    listSourcesInformation: PropTypes.object.isRequired,
};


let listSourcesInformation ={
    123: {
        "classType": "trojan-activity",
        "content" : ["GET, http_method,",
            "advert_key=, http_uri, fast_pattern,  content:app=, http_uri,"  
        ],
        "body": "alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (  msg:\"Downloader.MediaDrug.HTTP.C&C\"; flow:established,to_server;  content:\"GET\"; http_method; content:\"advert_key=\"; http_uri; fast_pattern;   content:\"app=\"; http_uri;  content:\"oslang=\"; http_uri; classtype:trojan-activity; sid:35586741; rev:0;)"
    },
    124: {
        "classType": "unsuccessful-user",
        "content" : "message",
        "body": "alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:\"Trojan.Staser.HTTP.C&C\"; flow:established,to_server; content:\"GET\"; http_method; content:\"/brandmachine/\"; http_uri; content:\"cid=\"; content:\"&headline\";content:\"&euid=\";classtype:trojan-activity; sid:31522997; rev:0;)",
    },
    125: {
        "classType": "attempted-user",
        "content" : "message",
        "body": "alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg: Downloader.DownloadSponsor.HTTP.ServerRequest ; flow:established,to_server; content: \"GET\"; http_method; content: clientid= ; content: &cid=; content: &pid=; content: &langcountry=; content:!api.chip-secured-download.de; http_header; classtype:trojan-activity; sid:31523070; rev:1;)",
    },
    126: {
        "classType": "web-application-activity",
        "content" : "message",
        "body": "alert udp $HOME_NET any -> any 53 (msg:\"Trojan-Spy.Agent.UDP.C&C\"; content:\"|01 00 00 01 00 00 00 00 00 00|\"; depth:10; offset:2; content:\"|06|madibi|05|f3322|03|net|00|\"; nocase; distance:0; fast_pattern; classtype:trojan-activity; sid:38600776; rev:0;)",
    },
  
};
/* 

 <React.Fragment>
                <div className="col-md-9 text-left"> Добавить файл </div>       
                <div class="custom-file">
                  <input type="file" class="custom-file-input" id="inputGroupFile04"/>
                  <label class="custom-file-label" for="inputGroupFile04">Выбрать файл</label>
                </div>
              <div class="input-group-append">
                <button class="btn btn-outline-secondary" type="button">Добавить файл</button>
              </div>
              </React.Fragment>

              <div className="input-group">
                <div className="custom-file">
                  <input type="file" className="custom-file-input" name="file" id="inputGroupFile" />
                    <label className="custom-file-label" name="file" for="inputGroupFile"> {text} </label>
                </div>
                  <div className="input-group-append">
                    <button className="btn btn-outline-primary" type="button">Добавить</button>
                  </div>
              </div> 
              <div>
                <input id="file-input" type="file" name="file" multiple/>
                <label for="file-input"></label>
                <span>Выберите файл или перетащите его сюда</span>
              </div>
            */

ReactDOM.render(<CreatePageRulesSOASourse 
    ss={ss}
    socketIo={socket}
    listSourcesInformation={listSourcesInformation}/>, document.getElementById("page-rules-soa"));

