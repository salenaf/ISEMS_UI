import React from "react";
import { Button, Badge, Card, Toast, Col, Row, Tooltip, OverlayTrigger } from "react-bootstrap";

import { ModalWindowConfirmMessage } from "../../modal_windows/modalWindowConfirmMessage.jsx";
import PropTypes from "prop-types";

import { data } from "jquery";
import { obj } from "../../../../configure/globalObject.js";

/* 
 * Search Sid
 * 
*/
export default class CreateBodySearchSid extends React.Component {
    constructor(props){
        super(props);
        //,  this.props.listShortEntity.listSourceRuleSOA
        
        this.state = {
            "modalWindowStatus": false,
            listRule:  {}, //this.createListSid.call(this, this.props.listShortEntity),
            buffSidOut:  null,
            

            color: "dark",
            saveOrNot: "",
            visible: "unvisible",
            filter_search: "",
            filter_error: {},

            typeListBD: this.createListType.call(this, this.props.listShortEntity),
            findSid:   {},
            contentEdit: "false",
            errorMsg: this.errorMsg.bind(this),
        };
        this.onBlurHandler = "";
        this.bodyForUpdate = ""; 
        // this.inPut = React.createRef();
        //this.resultS = "";
        this.contentEdit = "false";

 /*  */ this.typeList =[
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
        this.notSaveInfo     = this.notSaveInfo.bind(this);
        this.geveNewValueSID = this.geveNewValueSID.bind(this);
        
        this.showIconSaveChange =this.showIconSaveChange.bind(this);
        
        this.handlerEvents   = this.handlerEvents.call(this);

        this.showModalWindow    = this.showModalWindow.bind(this);
        //this.handlerSave        = this.handlerSave.bind(this);
        this.closeModalWindow   = this.closeModalWindow.bind(this);
        this.handlerSourceSave  = this.handlerSourceSave.bind(this);
        //  this.findSid        = this.findSid.bind(this, this.valueInPut );
        //   this.listenerSocketIoConn = this.listenerSocketIoConn.bind(this);
}

    handlerEvents(){
        console.log("func 'handlerEvents'");

        this.props.socketIo.on("result find SID", (data) => {
            this.setState({buffSidOut: data});
        });

        this.props.socketIo.on("result update value SID", (data) => {
            console.log(data);
        });
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
        let valueInPut = Number(this.state.filter_search);
        console.log(`______________`);
        console.log(`SID: ${valueInPut}`);
        console.log(this.state.filter_error);
        this.setState({
            filter_error: null,
        });

        this.props.socketIo.emit("sid_bd: find-sid", { sid: valueInPut });
    }

    readWrite(){
            
        let updateObj = this.state;
        if(this.state.contentEdit == "false"){
            updateObj.contentEdit ="true";
            updateObj.color= "info";
        } 
        this.setState(updateObj);
       
        //this.state.contentEdit="true";
    }

    // Валидация редактируемых данных
        wordOut(strBody, keywordStart, keywordEnd){
            let posStart = 0, posEnd = 0;
            let resultStr = null ;
            posStart = strBody.indexOf(keywordStart , posNull);
            if(posStart!=-1){
                posEnd = strBody.indexOf(keywordEnd, posStart+1);
                if(posEnd!=-1){
                    resultStr = strBody.slice(posStart + keywordStart.length , posEnd) ;
                }
        
            }
            return resultStr;
        }
       
        
    geveNewValueSID(e) {
        let value = e.target.textContent;
        let regexp = {
            msg:        /msg(:| :|: | : )("| "|" ).+?("| "|" )(;| ;)/gi,
            sid:        /sid(:| :|: | : )\d+?(;| ;)/gi,
            classtype:  /classtype(:| :|: | : ).+?(;| ;)/gi,
            space:      /:/gui,
        }  
        
        let err = {
            sid:"",
            msg:"",
            classtype:"",
        };
        let classType = false;
        let sid = false; 
        let msg = false;

        let result ={
            msg:        value.match(regexp.msg)|| [],
            sid:        value.match(regexp.sid)|| [],
            classtype:  value.match(regexp.classtype)|| [],
        };


        console.log("------------------");
        console.log(result.sid);
        console.log(result.msg);
        // проверка поля msg
        if(result.msg.length == 1){
            console.log(result.msg[0].match(regexp.space));
            if(result.msg[0].match(regexp.space).length != 1){
                err.msg = "Не корректно введён msg. Возможно потеряна \";\". msg: \"...\";"
                console.log(err);
            } else {   // успех
                msg = true;
            }
        }else{
            err.msg = "Не корректно введён msg. Возможно он отсутвует/дублируется или потеряно \":\". msg: \"...\";";
            console.log(err);
        }

        // проверка поля sid
        if(result.sid.length != 1){
            err.sid = "Не корректно введён sid. Возможно он отсутвует/дублируется, потеряно \":\" или потеряна \";\". sid: \/число\/";
            console.log(err);
        }else{
            //успех 
            sid = true;
        }

        // проверка поля classType
        if(result.classtype.length == 1){
            console.log(result.classtype[0].match(regexp.space));
            if(result.classtype[0].match(regexp.space).length != 1){
                err.classtype = "Не корректно введён classtype. Возможно потеряна \";\". classtype: ...;"
                console.log(err);
            } else {   // успех
                classType = true;
            }
        }else{
            err.classtype = "Не корректно введён classtype. Возможно он отсутвует/дублируется или потеряно \":\". classtype: ...;";
            console.log(err);
        }

        if(sid&msg&classType){
            this.bodyForUpdate = value;
        } else {
            this.bodyForUpdate = "";
        }

        this.setState({
            filter_error: err,
        });
        // console.log(value);
    }

    notSaveInfo(){
        this.state.saveOrNot = "";
        this.setState({
            filter_error: null,
        });
        
        this.showModalWindow();
        
    }

    saveInfo(){
        if(this.bodyForUpdate != ""){
            this.state.saveOrNot = "save";
            this.showModalWindow();
        } 
    }
    // Показать модальное окно
    showModalWindow(){
        this.setState({ "modalWindowStatus": true });
    }

    //Что делать модальному окну принажатии "Подтвердить"
    handlerSourceSave(){
        let flag = this.state.saveOrNot;
        if(flag == "save"){
            if(this.bodyForUpdate != ""){
                this.props.socketIo.emit("update value SID", {
                    checkSID: this.state.buffSidOut.sid,
                    updateBody: this.bodyForUpdate,
                 });
                
                //this.state.displayedInfo = this.bodyForUpdate;
            }
        } else {
            this.setState({
                filter_error: null,
            });
        }
        let updateObj = this.state;

        updateObj.contentEdit="false";
        updateObj.color= "dark";
        updateObj.saveOrNot = "";
        this.setState(updateObj);
        this.closeModalWindow();

        this.handleSubmit();
    }

    //Закрыть модальное окно
    closeModalWindow(){
        this.setState({ "modalWindowStatus": false });
    }

    //this.props.userPermissions.management_sources.element_settings.edit.status
    showIconSaveChange(){
        if(this.state.contentEdit == "true"){
            return (
                <React.Fragment>
                    <OverlayTrigger key="Save" placement="top-end" overlay={<Tooltip>Сохранить изменения</Tooltip>}>   
                        <a className = "btn btn-sm" onClick={this.saveInfo.bind(this)} >
                            <img className="clickable_icon" src="./images/icons-save-2.png" alt= "Сохранить изменения" ></img>
                        </a>
                    </OverlayTrigger> 
                   {/*<pre><p> </p></pre>*/} 
                   <OverlayTrigger key="Not save" placement="top-end" overlay={<Tooltip>Не сохранять изменения</Tooltip>}>
                        <a className = "btn  btn-sm" onClick={this.notSaveInfo.bind(this)}>
                            <img className="clickable_icon" src="./images/icons8-delete-16.png" alt ="Не сохранять изменения" ></img>
                        </a>
                    </OverlayTrigger>
                </React.Fragment>
            );
        }else{
            return (<React.Fragment></React.Fragment>);
        }
    }

    resultSearch(){
        //const {  buffSidOut } = this.state;
        if(this.state.buffSidOut == null) {
            visPole = "unvisible"; 
            return;
        } 
        let inSidBD = this.state.buffSidOut;
        console.log("_______________");
        console.log(inSidBD.body);

        let visPole = "visible";
        let color = this.state.color;
        let  disable = {
            str: "disabled",
            bool: "true"
        };
        let  disable1 = {
            str: "",
            bool: "false"
        };

        return <React.Fragment>
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
                                <OverlayTrigger placement="top-end" overlay={<Tooltip>Редактировать</Tooltip>}>
                                    <a className = {`btn btn-sm ${disable1.str}`} onClick={this.readWrite.bind(this)} aria-disabled = {`${disable1.bool}`}>
                                        <img className="clickable_icon" src="./images/icons8-edit-1.png" alt="редактировать"/>
                                    </a> 
                                </OverlayTrigger>
                                {/*<pre><p> </p></pre>*/} 
                                    {this.showIconSaveChange()} 
                            </div>
                            {this.state.messageInfo}
                        </h5>
                        <div className="card-body" 
                            contentEditable={this.state.contentEdit}
                            suppressContentEditableWarning={true}
                            onInput     ={this.geveNewValueSID} >
                            <p className="card-text"> {inSidBD.body}</p> 
                        </div>
                         
                    </div>
                   
                </div>
            </div>
            <ModalWindowConfirmMessage 
                    show={this.state.modalWindowStatus}
                    onHide={this.closeModalWindow}
                    msgBody={`Вы действительно ${(this.state.saveOrNot == "save") ? "хотите сохранить": "не хотите сохранять"} изменения?`}
                    msgTitle={`${(this.state.saveOrNot == "save") ? "Сохранить": "Не сохранять"} изменения`}
                    nameDel={this.state.saveOrNot}
                    handlerConfirm={this.handlerSourceSave} />
        </React.Fragment>;
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

    errorMsg(){
        console.log(this.state.filter_error);
        if(this.state.filter_error!=null){
            return <div>
                <p>{this.state.filter_error.msg}</p>
                <p>{this.state.filter_error.sid}</p>
                <p>{this.state.filter_error.classtype}</p>
            </div>
        } else {
            return <div> </div>
        }
    };

    render(){
        const {  filter_error } = this.state;
        let k = 0;
        let typeList = this.state.typeListBD;
        for(let j=0; j < typeList.length; j++){
            let object  = typeList[j];
            k+= object.count;
        }
        let error = filter_error;
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
                {this.state.errorMsg()} 
         </React.Fragment>
        );
    }
}

CreateBodySearchSid.propTypes ={
    socketIo: PropTypes.object.isRequired,
    listShortEntity: PropTypes.object.isRequired,
       //hundlerEvents: PropTypes.func.isRequired, 
       // listSourcesInformation: PropTypes.object.isRequired,
};