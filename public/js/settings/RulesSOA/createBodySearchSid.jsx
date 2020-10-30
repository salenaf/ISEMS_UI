import React from "react";
import { Button, Badge, Card, Col, Row, Tooltip, OverlayTrigger } from "react-bootstrap";


import PropTypes from "prop-types";

//const async = require("async");
//const models = require("../../../../controllers/models");

//
import ModalWindowAddEntity from "../../modalwindows/modalWindowAddEntity.jsx";
import { data } from "jquery";
//const informationForPageSOARules = require("../../../libs/management_settings/informationForPageSOARules"); 

export default class CreateBodySearchSid extends React.Component {
    constructor(props){
        super(props);
        //,  this.props.listShortEntity.listSourceRuleSOA
        
        this.state = {
            listRule:  {}, //this.createListSid.call(this, this.props.listShortEntity),
            buffInSid:  null,
            color: "dark",
            saveIcons: "./images/icons-save-0.png",
            visible: "unvisible",
            filter_search: "",
            typeListBD: this.createListType.call(this, this.props.listShortEntity),
            findSid:   {},
            contentEditable: "false",// this.findSid.call(this, this.props.listShortEntity),
            //"checkboxMarkedSourceDel": this.createStateCheckboxMarkedSourceDel.call(this),
        };
        this.onBlurHandler = "";
        this.bodyForUpdate = ""; 
        // this.inPut = React.createRef();
        //this.resultS = "";
        this.contentEditable = "false";

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
        
        this.resultSearch    = this.resultSearch.bind(this);
        this.handleSubmit    = this.handleSubmit.bind(this); 
        this.typeCount       = this.typeCount.bind(this);
        this.onChangeSearch  = this.onChangeSearch.bind(this);
        
        this.readWrite       = this.readWrite.bind(this);
        this.saveInfo        = this.saveInfo.bind(this);
        this.geveNewValueSID = this.geveNewValueSID.bind(this);
        this.handlerEvents   = this.handlerEvents.call(this);
        this.modalWindowSave = this.modalWindowSave.bind(this);
        //  this.findSid        = this.findSid.bind(this, this.valueInPut );
       

        //   this.listenerSocketIoConn = this.listenerSocketIoConn.bind(this);

        
    }

    handlerEvents(){
        console.log("func 'handlerEvents'");

        this.props.socketIo.on("result find SID", (data) => {
            console.log(data);
            this.setState({buffInSid: data});
            
        });

        this.props.socketIo.on("result update value SID", (data) => {
            console.log(data);
            // this.setState({buffInSid: data});
            
        });
    }

    /*  listenerSocketIoConn(){
        this.props.socketIo.on("rule soa", (data) => {
            this.setState({ listRule: this.createListSid.call(this, data.arguments)});
        });
    }*/

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
    createListType(listShortEntity){
        
        let listTmp = listShortEntity.listCountClassType.map((object) => {
            return {
                typeName: object._id,
                count:    object.count,
            };

        });
        //listTmp.sort((prev, next) => prev.sid - next.sid);

        return listTmp;

    }
    createListSid(listShortEntity){
        //console.log("createListOrganization START...");

        let listTmp = {};

        listTmp = listShortEntity.shortListRuleSOA.map((item) => {
            return { 
                sid: item.sid, 
                classType: item.classType,
                body: item.body,
                msg: item.msg,
            };

        });
        return listTmp;
    }
    
    findSid(listShortEntity, valueInPut=26900){
        //listShortEntity.inPutSid = valueInPut;
        console.log(valueInPut);
        listShortEntity.findSid.inPutFindSid = valueInPut;

        let a = listShortEntity.findSid.map((item) => {
            return { 
                sid: item.sid, 
                classType: item.classType,
                body: item.body,
                msg: item.msg,
            };
        }); 

        console.log("Рeзультат");
        console.log(a);

        return a;
    }

    handleSubmit(event) {
        console.log("gdgfgfhgh");

        let valueInPut = Number(this.state.filter_search);

        console.log(`SID: ${valueInPut}`);

        this.props.socketIo.emit("sid_bd: find-sid", { sid: valueInPut });
      
    }


                                            
    /// Тута вставка  
    /*inputField(){
        let outPutTabl = <React.Fragment>
            <div className={visPole}>
                <div className="card text-left">
                    <h5 className="card-header">
                                     Sid: {inSidBD.sid}   
                        <br/>
                                     Тип:  {inSidBD.classType}
                    </h5>

                    <div className="card-body">
                        <p className="card-text">{inSidBD.body}</p>
                    </div>
                </div></div>
        </React.Fragment>;
        return outPutTabl;
    }*/
    readWrite(){
            
        let updateObj = this.state;
        if(updateObj.contentEditable == "false"){
            updateObj.contentEditable="true";
            //updateObj.visible = "visible";
            updateObj.color= "info";
            updateObj.saveIcons= "./images/icons-save-2.png";
        } else {
                        
            let checkSave =   confirm("Сохранить изменения?");
            
            if(!checkSave){
                checkSave =   confirm("Ваши изменения не будут сохранены.\n Сохранить изменения?");
            } 
            if(checkSave){
                this.saveInfo(this);
            } else {
                alert("Изменения не сохранены");
            }  
            
            updateObj.contentEditable="false";
            updateObj.color= "dark";
            updateObj.saveIcons= "./images/icons-save-0.png";
        }
        this.setState(updateObj);
       
        //this.state.contentEditable="true";
    }

    geveNewValueSID(e) {
        let value = e.target.textContent;
        //console.log("------------------------");

        this.bodyForUpdate = value;
        // console.log(value);
    }

    saveInfo(){

        let updateObj = this.state;
        //modalWindowSave();
        if(updateObj.contentEditable == "true"){
            
        
            this.setState(updateObj);

            // this.bodyForUpdate = "alert tcp -> $EXTERNAL_NET any (msg:\"SQL sa login failed\"; flow:to_client,established; content:\"Login failed for user 'sa'\"; fast_pattern:only; metadata:policy balanced-ips drop, policy connectivity-ips drop, policy max-detect-ips drop, policy security-ips drop, ruleset community; reference:bugtraq,4797; reference:cve,2000-1209; reference:nessus,10673; classtype: 1unsuccl-user1; sid:688; rev:17;)";
            if(this.bodyForUpdate != ""){
                this.props.socketIo.emit("update value SID", {
                    checkSID: this.state.buffInSid.sid,
                    updateBody: this.bodyForUpdate,
                });
                this.handleSubmit();
                alert("Изменения сохранены :3");
            }
            updateObj.contentEditable = "false";
            updateObj.color= "dark";
            updateObj.saveIcons= "./images/icons-save-0.png";
            this.setState(updateObj);
        }
    }
    //
    modalWindowSave(){

        return <React.Fragment>
            <div className="modal fade" id="exampleModalCenter" tabIndex="-1" role="dialog" aria-labelledby="exampleModalCenterTitle" aria-hidden="false">
                <div className="modal-dialog modal-dialog-centered" role="document">
                    <div className="modal-content">
                        <div className="modal-header">
                            <h5 className="modal-title" id="exampleModalLongTitle">Сохранение данных</h5>
                            <button type="button" className="close" data-dismiss="modal" aria-label="Close">
                                <span aria-hidden="true">&times;</span>
                            </button>
                        </div>
                        <div className="modal-body">
                                                Хотите сохранить изменения?
                        </div>
                        <div className="modal-footer">
                            <button type="button" className="btn btn-secondary" data-dismiss="modal">Не сохратять</button>
                            <button type="button" className="btn btn-primary"   data-dismiss="modal">Сохранить изменения</button>
                        </div>
                    </div>
                </div>
            </div> 
        </React.Fragment>;
    }/**/
    resultSearch(){
        // const {  buffInSid } = this.state;
        
        let inSidBD =this.state.buffInSid;
        if(inSidBD==undefined) {
            visPole = "unvisible"; 
            return;
        }

        let visPole = "visible";
        let color = this.state.color;
        
        let saveIcon = this.state.saveIcons;
        // this.state.bodyForUpdate;
        // card-header border-${color}
        let edit = this.state.contentEditable;
        //  <p className="card-text">
        let outPutTabl = <React.Fragment>
            <div className={visPole}> 
                <div className="text-left">     
                    <div className={` card mb-3 border-${color}`}>
                        <h5 className= {`alert alert-${color}`}>
                            <div className="media">
                                <div className="media-body">
                                    <p className="mt-0 mb-1">
                                        Sid: {inSidBD.sid} 
                                    </p>
                                    Тип:  {inSidBD.classType} 
                                </div>
                                <a className="button disabled" onClick={this.readWrite.bind(this)} data-toggle="tooltip" data-placement="top" title="Редактировкать">
                                    <img className="clickable_icon" src="./images/icons8-edit-1.png" alt="редактировать"/>
                                </a> 
                                <pre><p> </p></pre>
                                <a className="button" onClick={this.saveInfo.bind(this)} data-toggle="tooltip" data-placement="top" title="Сохранить изменения">
                                    <img className="clickable_icon" src={saveIcon} alt="сохранить"/>
                                </a>     
                            </div>
                            { this.modalWindowSave()}
                        </h5>
                        <div className="card-body" 
                            contentEditable={edit}
                            onInput={this.geveNewValueSID}>
                            <p className="card-text"> {inSidBD.body}</p> 
                        </div>
                        
                    </div>
                </div>
            </div>

        </React.Fragment>;
        console.log(inSidBD.body);
        return outPutTabl;
    }
    
    typeCount(){
        let resultType = "";
        /* {typeList.map(el => (   ))}*/
                                   
        let typeInPut = [];
        let j = 0;
        let typeList = this.state.typeListBD;
        let k = 0;
        let t1="",t2="",t3="",t4="";
        for(let i=0; i<this.typeList.length; i+=4){
            if(typeList[i  ]!= null) { t1 = `${typeList[i  ].typeName}: ${typeList[i  ].count}`; k+= typeList[i  ].count;}
            if(typeList[i+1]!= null) { t2 = `${typeList[i+1].typeName}: ${typeList[i+1].count}`; k+= typeList[i+1].count;} 
            if(typeList[i+2]!= null) { t3 = `${typeList[i+2].typeName}: ${typeList[i+2].count}`; k+= typeList[i+2].count;}
            if(typeList[i+3]!= null) { t4 = `${typeList[i+3].typeName}: ${typeList[i+3].count}`; k+= typeList[i+3].count;}
            
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
        console.log(k);

        let i = 0;
        resultType =    <React.Fragment>
            <div className="container text-left">
                {typeInPut.map(el => ( 
                    <div key={`key_${i++}`}> {el} </div>
                ))}
            </div>
        </React.Fragment>;
     
        return resultType;
    }



    render(){
        // {location.reload();}
        let k = 0;
        let typeList = this.state.typeListBD;
        for(let j=0; j < typeList.length; j++){
            let object  = typeList[j];
            k+= object.count;
        }

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

                {/*                <Form className= "form-inline">*/}
                <Row>
                    <Col md={6}>
                        <input className="form-control mr-sm-2" placeholder="Введите sid" value = {this.state.filter_search} onChange = {this.onChangeSearch}  type="search" aria-label="Search"/>
                    </Col>
                    <Col md={6} className="text-left">
                        <button className="btn btn-outline-success my-2 my-sm-0"  onClick={this.handleSubmit.bind(this)} type="submit"> Поиск </button>  
                    </Col>
                </Row>
                {/*</Form>*/}
                <br/>

                <div className="col-md-8 text-left"> { this.resultS} </div>
                {this.resultSearch()}
            </React.Fragment>
        );
    }
}
//onClick={this.handleSubmit.bind(this)} this.resultS
CreateBodySearchSid.propTypes ={
    socketIo: PropTypes.object.isRequired,
    hundlerEvents: PropTypes.func.isRequired,
    listShortEntity: PropTypes.object.isRequired,
    // listSourcesInformation: PropTypes.object.isRequired,
};