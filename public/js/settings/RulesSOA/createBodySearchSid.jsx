import React from "react";
import { Button, Badge, Card, Col, Form, Row } from "react-bootstrap";
import PropTypes from "prop-types";

import ModalWindowAddEntity from "../../modalwindows/modalWindowAddEntity.jsx";

export default class CreateBodySearchSid extends React.Component {
    constructor(props){
        super(props);

        this.state = {
            listSid: this.createListSid.call(this),
            inPutSid: [ ],
            filter_search: "",
        };
        this.inPut = React.createRef();
        this.resultS = "";
        
        this.typeList =[
            { size: 1,  nameType: "trojan-activity", },
            { size: 2,  nameType: "unsuccessful-user"},
            { size: 3,  nameType: "attempted-admin"},
            { size: 4,  nameType: "attempted-user"},
            { size: 5,  nameType: "attempted-dos"},
            { size: 6,  nameType: "protocol-command-decode"},
            { size: 7,  nameType: "misc-attack"},
            { size: 8,  nameType: "web-application-activity"},
            { size: 9,  nameType: "web-application-attack"},
            { size: 10, nameType: "successful-recon-limited" },
            { size: 11, nameType: "successful-admin" },  
            { size: 12, nameType: "successful-user" },
            { size: 13, nameType: "policy-violation"},
        ];


        console.log(this.props.socketIo);

        this.resultSearch = this.resultSearch.bind(this);
        this.handleSubmit = this.handleSubmit.bind(this); 
        this.typeCount    = this.typeCount.bind(this);
        this.onChangeSearch     = this.onChangeSearch.bind(this);
        //this.changeSid    = this.changeSid.bind(this)

        this.hundlerEevents.call(this);
    }
   

    onChangeSearch(e) {
        let regexp =   /[^0-9]/g;
        let value = e.target.value;
        value = value.replace(/^\s/, "");
        value = value.replace(/ {2}/, " ");
        value = value.replace(regexp, "");
        //value = value.substr(0, 25);
        this.setState({
            filter_search: value
        });
    }
 
    createListSid(){
        //console.log("createListOrganization START...");

        let listTmp = {};
        for(let source in this.props.listSourcesInformation){
            listTmp[source] = {
                "classType" : this.props.listSourcesInformation[source].classType,
                "content"   : this.props.listSourcesInformation[source].content,
                "body"      : this.props.listSourcesInformation[source].body
            };
        }

        return listTmp;
    }

    hundlerEevents(){
        this.props.socketIo.on("rules soa", (data) => {
            console.log(data);
        });
    }

    handleSubmit(event) {
        const {listSid} = this.state;
        let valueInPut = Number(this.state.filter_search);
        
        console.log(this.state.filter_search);

        this.props.socketIo.emit("rules soa", {
            "actionType": "search",
            "options": {
                "sid": this.state.filter_search
            },
        });

        let updateObj = this.state;
        updateObj.inPutSid.pop();
        let masang = "";
        if(valueInPut > 0){
            if(listSid[valueInPut]==undefined){
                masang ="Sid не найден";
                // console.log(listSid[valueInPut]);
            }   
            else{            
                updateObj.inPutSid.push(valueInPut);
            } 
        } else {
            if(valueInPut == 0){
                masang = "Введите значение Sid";
                // alert(masang); 
            }
        }
        this.resultS = masang;
        
        this.setState(updateObj);
        
        event.preventDefault();
    }

    resultSearch(){
        const {  listSid, inPutSid } = this.state;

        // if(this.inPutSid==undefined) return;

        let visPole = "visible";

        if(inPutSid.length == 0){
            visPole = "unvisible";
            return;
        } else {
            console.log(inPutSid.length);
        
            let sidId   = inPutSid[0];
            let typeSid = "Что-то";
            let textSid = "";

            typeSid = listSid[sidId].classType;
            textSid = listSid[sidId].body;
            this.resultS = "";
            let outPutTabl = <React.Fragment>
                <div className={visPole}>
                    <div className="card text-left">
                        <h5 className="card-header">
                                     Sid: {sidId}   
                            <br/>
                                     Тип:  {typeSid}
                        </h5>

                        <div className="card-body">
                            <p className="card-text">{textSid}</p>
                        </div>
                    </div></div>
            </React.Fragment>;
            return outPutTabl;
        }
    }
    
    /*            
      <input className="form-control mr-sm-2" type="search" placeholder="Введите sid" ref={this.inPut}  aria-label="Search"/>  
    <table>
                        <body>
                            <table>
                                <tr >
                                    <td>Типа "один": {n-1}</td>
                                    <td>типа "два": {n-2}</td>
                                    <td>типа "три" {n-3}</td>
                                </tr>
                                <tr>
                                    <td>Типа "один": {n-1}</td>
                                    <td>типа "два": {n-2}</td>
                                    <td>типа "три" {n-3}</td>
                                </tr>
                            </table>
                        </body>
                    </table>
      
       {typeList.map(el => ( ))}
                <div className="p-2">Flex элемент 1</div>
                <div className="p-2">Flex элемент 2</div>
                <div className="p-2">Flex элемент 3</div>
      
                    */
    typeCount(){
        let resultType = "";
        /* {typeList.map(el => (   ))}*/
                                   
        let typeInPut = [];
        let j = 0;
        
        let k = 0;
        let t1="",t2="",t3="",t4="";
        for(let i=0; i<this.typeList.length; i+=4){
            if(this.typeList[i  ]!= null) { t1 = `${this.typeList[i  ].nameType}: ${this.typeList[i  ].size}`; k+= this.typeList[i  ].size; }
            if(this.typeList[i+1]!= null) { t2 = `${this.typeList[i+1].nameType}: ${this.typeList[i+1].size}`; k+= this.typeList[i+1].size;} 
            if(this.typeList[i+2]!= null) { t3 = `${this.typeList[i+2].nameType}: ${this.typeList[i+2].size}`; k+= this.typeList[i+2].size;}
            if(this.typeList[i+3]!= null) { t4 = `${this.typeList[i+3].nameType}: ${this.typeList[i+3].size}`; k+= this.typeList[i+3].size;}
            
            typeInPut[j] =   <div className="row">
                <div className="col">{t1}</div>
                <div className="col">{t2}</div>
                <div className="col">{t3}</div>
                <div className="col">{t4}</div>
                <div className="w-100"></div>
            </div>; 
            
            j++; t1="";t2="";t3="";t4="";
        }     
        /* */
        console.log(`${k}`);

        resultType =    <React.Fragment>
            <div className="container text-left">
                {typeInPut.map(el => ( 
                    <div> {el} </div>
                ))}
            </div>
        </React.Fragment>;
     
        return resultType;
    }

    render(){
        
        let k = 0;
        for(let j=0; j < this.typeList.length; j++){
            k+=this.typeList[j].size;
        }
        this.typeList.sort(function (a, b) {
            if (a.nameType > b.nameType) {
                return 1;
            }
            if (a.nameType < b.nameType) {
                return -1;
            } // a должно быть равным b
            return 0;
        });
        return (
            <React.Fragment>
                <div className="text-left">
                    <a className="nav-link" data-toggle="collapse" href="#typeList" role="button" aria-expanded="false" aria-controls="typeList">
                        Всего базе {k} sid (нажмите для получения информации)
                    </a> 
                </div>
                <div className="collapse" id="typeList">
                    <div className="card card-body">
                        {this.typeCount()}
                    </div>
                </div>
                <br/>
                <form className= "form-inline">
                    <input className="form-control mr-sm-2" placeholder="Введите sid" value = {this.state.filter_search} onChange = {this.onChangeSearch}  type="search" aria-label="Search"/>
                    <button className="btn btn-outline-success my-2 my-sm-0"  onClick={this.handleSubmit.bind(this)} type="submit"> Поиск </button>
                </form>
                <br/>

                <div className="col-md-8 text-left"> {this.resultS} </div>
                {this.resultSearch()}
            </React.Fragment>
        );
    }
}

CreateBodySearchSid.propTypes ={
    socketIo: PropTypes.object.isRequired,
    listSourcesInformation: PropTypes.object.isRequired,
};