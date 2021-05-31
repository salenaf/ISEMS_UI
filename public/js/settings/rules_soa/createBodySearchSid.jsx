import React from "react";
import { Col, Row, Tooltip, OverlayTrigger } from "react-bootstrap";

import { ModalWindowConfirmMessage } from "../../commons/modalWindowConfirmMessage.jsx";
import PropTypes from "prop-types";
import ClearIcon from "@material-ui/icons/Clear";

/* 
 * Search Sid
 * 
*/
export default class CreateBodySearchSid extends React.Component {
    constructor(props){
        super(props);
       
        this.state = {
            "modalWindowStatus": false,
            listRule:  {}, 
            buffSidOut:  null,
            msgModWindow:{
                msgBody:"",
                msgTitle:"",
                comandModWindow:"",
            },

            color: "dark",
            saveOrNot: "",
            visible: "unvisible",
            filter_search: "",
            filter_error: null,

            typeListBD: this.createListType.call(this, this.props.listShortEntity),
            findSid:   {},
            contentEdit: "false",
            errorMsg: this.errorMsg.bind(this),

        };
        this.onBlurHandler = "";
        this.bodyForUpdate = ""; 
        this.contentEdit = "false";

        this.typeList =[        ];
     
        this.resultSearch    = this.resultSearch.bind(this);
        this.handleSubmit    = this.handleSubmit.bind(this); 
        this.typeCount       = this.typeCount.bind(this);
        this.onChangeSearch  = this.onChangeSearch.bind(this);
        
        this.readWrite       = this.readWrite.bind(this);
        this.saveInfo        = this.saveInfo.bind(this);
        this.notSaveInfo     = this.notSaveInfo.bind(this);
        this.deleteInfo      = this.deleteInfo.bind(this);
        this.geveNewValueSID = this.geveNewValueSID.bind(this);
        this.handleKeyPress  = this.handleKeyPress.bind(this);
        this.showIconSaveChange =this.showIconSaveChange.bind(this);
        
        this.handlerEvents   = this.handlerEvents.call(this);

        this.showModalWindow    = this.showModalWindow.bind(this);
        this.closeModalWindow   = this.closeModalWindow.bind(this);
        this.handlerSourceSave  = this.handlerSourceSave.bind(this);
    }

    handlerEvents(){
        this.props.socketIo.on("result find SID", (data) => {
            this.setState({buffSidOut: data});
        });

        this.props.socketIo.on("result update value SID", (data) => {
            console.log(data);
        });
        this.props.socketIo.on("result delete value SID", (data) => {
            console.log(data);
        });
    }

    onChangeSearch(e) {
        let regexp =   /[^0-9]/g;
        let value = e.target.value;
        value = value.replace(/^\s/, "");
        value = value.replace(/ {2}/, " ");
        value = value.replace(regexp, "");
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
        return listTmp;
    }
    createListSid(listShortEntity){
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
        listShortEntity.findSid.inPutFindSid = valueInPut;

        let a = listShortEntity.findSid.map((item) => {
            return { 
                sid: item.sid, 
                classType: item.classType,
                body: item.body,
                msg: item.msg,
            };
        }); 
        return a;
    }

    handleSubmit(event) {
        let valueInPut = Number(this.state.filter_search);
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
        };  
        
        let err = {
            sid: null,
            msg:null,
            classtype:null,
            noChange: null,
        };
        let classType = false;
        let sid = false; 
        let msg = false;
        let noChange = false;

        let result ={
            msg:        value.match(regexp.msg)|| [],
            sid:        value.match(regexp.sid)|| [],
            classtype:  value.match(regexp.classtype)|| [],
        };

        if(result.msg.length == 1){
            if(result.msg[0].match(regexp.space).length != 1){
                err.msg = "Не корректно введён msg. Возможно потеряна \";\". msg: \"...\";";
            } else {   // успех
                msg = true;
            }
        }else{
            err.msg = "Не корректно введён msg. Возможно он отсутвует/дублируется или потеряно \":\". msg: \"...\";";
        }

        // проверка поля sid
        if(result.sid.length != 1){
            err.sid = "Не корректно введён sid. Возможно он отсутвует/дублируется, потеряно \":\" или потеряна \";\". sid: \/число\/";
        }else{          //успех 
            sid = true;
        }

        // проверка поля classType
        if(result.classtype.length == 1){
            if(result.classtype[0].match(regexp.space).length != 1){
                err.classtype = "Не корректно введён classtype. Возможно потеряна \";\". classtype: ...;";
            } else {   // успех
                classType = true;
            }
        }else{
            err.classtype = "Не корректно введён classtype. Возможно он отсутвует/дублируется или потеряно \":\". classtype: ...;";
        }
        let oldValue = this.state.buffSidOut.body;

        if((value.indexOf(oldValue) !=-1 )){
            err.noChange = "Изменения не найдены";
        } else{
            noChange = true;
        }

        // Если есть нет ошибок, присваивается новое значение
        if(sid&msg&classType&noChange){
            this.bodyForUpdate = value;
        } else {
            this.bodyForUpdate = "";
        }

        this.setState({
            filter_error: err,
        });
    }

    deleteInfo(){
        // eslint-disable-next-line react/no-direct-mutation-state
        this.state.saveOrNot = "delete";
        this.state.msgModWindow ={
            msgBody:    "Вы действительно хотите безвозвратно удалить выбранное правило?",
            msgTitle:   "Удалить выбранное правило",
            comandModWindow: "delete",
        };
        this.showModalWindow();
        
    }

    notSaveInfo(){
        this.state.saveOrNot = "";
        this.setState({
            filter_error: null,
        });
        this.state.saveOrNot = "no save";
        this.state.msgModWindow = {
            msgBody:    "Вы действительно не хотите сохранять изменения?",
            msgTitle:   "Не сохранять изменения",
            comandModWindow: "not save",
        };
        this.showModalWindow();
        
    }

    saveInfo(){
        if(this.bodyForUpdate != ""){
            this.state.saveOrNot = "save";
            this.state.msgModWindow ={
                msgBody:    "Вы действительно хотите сохранить изменения?",
                msgTitle:   "Сохранить изменения",
                comandModWindow: "save",
            };
            this.showModalWindow();
        } else{
            this.setState({
                filter_error: {
                    noChange: "Изменения не найдены",
                },
            });  
        }
    }
    // Показать модальное окно
    showModalWindow(){
        this.setState({ "modalWindowStatus": true });
    }

    //Что делать модальному окну принажатии "Подтвердить"
    handlerSourceSave(){
        let flag = this.state.msgModWindow.comandModWindow;
        switch(flag) {
        case "save":
            if(this.bodyForUpdate != ""){
                this.props.socketIo.emit("update value SID", {
                    checkSID: this.state.buffSidOut.sid,
                    updateBody: this.bodyForUpdate,
                });
            }
            break;
        case "delete":  
            this.props.socketIo.emit("delete value SID", {
                checkSID: this.state.buffSidOut.sid,
            });
            this.setState({
                filter_error: null,
            });
            break;
        case "not save":  
            this.bodyForUpdate = this.state.buffSidOut.body;
            this.setState({
                filter_error: null,
            });
            break;
        default:
            break;
        }
        this.state.msgModWindow={
            msgBody:"",
            msgTitle:"",
            comandModWindow:"",
        };
        
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

    
    showIconSaveChange(disableEdit){
        if(this.state.contentEdit == "true"){
            return (
                <React.Fragment>
                    <OverlayTrigger key="Save" placement="top-end" overlay={<Tooltip>Сохранить изменения</Tooltip>}>   
                        <a className = "btn btn-sm" onClick={this.saveInfo.bind(this)} >
                            <img className="clickable_icon" src="./images/icons-save-2.png" alt= "Сохранить изменения" ></img>
                        </a>
                    </OverlayTrigger> 
                    <OverlayTrigger key="Not save" placement="top-end" overlay={<Tooltip>Не сохранять изменения</Tooltip>}>
                        <a className = "btn  btn-sm" onClick={this.notSaveInfo.bind(this)}>
                            <img className="clickable_icon" src="./images/icons8-delete-16.png" alt ="Не сохранять изменения" ></img>
                        </a>
                    </OverlayTrigger>
                </React.Fragment>
            );
        } else {
            return (
                <React.Fragment>
                    <OverlayTrigger placement="top-end" overlay={<Tooltip>Редактировать</Tooltip>}>
                        <a className = {`btn btn-sm ${disableEdit.str}`} onClick={this.readWrite.bind(this)} aria-disabled = {`${disableEdit.bool}`}>
                            <img className="clickable_icon" src="./images/icons8-edit-1.png" alt="редактировать"/>
                        </a> 
                    </OverlayTrigger>
                </React.Fragment>
            );
        }
    }

    resultSearch(){
        if(this.state.buffSidOut == null) {
            visPole = "unvisible"; 
            return;
        } 
        let inSidBD = Object.assign({},this.state.buffSidOut);

        let visPole = "visible";
        let color = this.state.color;
        
        let  disableEdit = {
            str: "disabled",
            bool: "true"
        };  
        let disableDelete = {
            str: "disabled",
            bool: "true"
        };
        if(this.props.userPermissions.edit.status){
            // if(this.props.userPermissions.create.status){    
        }
        if(this.props.userPermissionsSearch.edit.status){
            disableEdit = {
                str: "",
                bool: "false"
            };
        }
        if(this.props.userPermissions.delete.status){
            disableDelete = {
                str: "",
                bool: "false"
            };
        }
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
                                {this.showIconSaveChange(this, disableEdit)}
                                
                                <OverlayTrigger placement="top-end" overlay={<Tooltip>Удалить правило</Tooltip>}>
                                    <a className = {`btn btn-sm ${disableDelete.str}`} onClick={this.deleteInfo.bind(this)} aria-disabled = {`${disableDelete.bool}`}>
                                        <img className="clickable_icon" src="./images/trash-2x.png" alt="удалить"/>
                                    </a> 
                                </OverlayTrigger>                                     
                            </div>
                            {this.state.messageInfo}
                        </h5>
                        <div className="card-body" 
                            contentEditable ={this.state.contentEdit}
                            suppressContentEditableWarning={true}
                            onInput         = {this.geveNewValueSID} >
                            <p className="card-text"> {inSidBD.body}</p> 
                        </div>
                         
                    </div>
                   
                </div>
            </div>
            <ModalWindowConfirmMessage 
                show={this.state.modalWindowStatus}
                onHide={this.closeModalWindow}
                msgBody= {this.state.msgModWindow.msgBody}
                msgTitle={this.state.msgModWindow.msgTitle}
                nameDel={this.state.saveOrNot}
                handlerConfirm={this.handlerSourceSave} />
        </React.Fragment>;
    }
    
    typeCount(){
        let resultType = "";                             
        let typeInPut = [];
        let j = 0;
        let typeList = this.state.typeListBD;
        let k = 0;
        let t1="",t2="",t3="",t4="";
        for(let i=0; i<typeList.length; i+=4){
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
        if(this.state.filter_error!=null){
            let msg = <div></div>;
            let sid = <div></div>;
            let classtype = <div></div>;
            let noChange = <div></div>;
            if(this.state.filter_error.msg!=null)
                msg = <div  className="alert alert-danger" role="alert">
                    <h6> {this.state.filter_error.msg}</h6>
                </div>;
            if(this.state.filter_error.sid!=null)        
                sid = <div  className="alert alert-danger" role="alert">
                    <h6>{this.state.filter_error.sid}   </h6> 
                </div>;
            if(this.state.filter_error.classtype!=null)
                classtype = <div  className="alert alert-danger" role="alert">
                    <h6>      {this.state.filter_error.classtype}  </h6>       
                </div>;
            if(this.state.filter_error.noChange!=null)
                noChange = <div  className="alert alert-danger" role="alert">
                    <h6>  {this.state.filter_error.noChange}</h6>               
                </div>;
 

            return <div>
                {msg}
                {sid}
                {classtype}
                {noChange}
            </div>;
        } else {
            return <div> </div>;
        }
    }
    handleKeyPress(event) {
        if(event.key == "Enter"){
            this.addPortNetworkIP();
        }
    }
    
    render(){
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
                <Row>
                    <Col md={6}>
                        <input className="form-control mr-sm-2" placeholder="Введите sid" value = {this.state.filter_search} onChange = {this.onChangeSearch}  type="search" aria-label="Search"/>
                        
                    </Col>
                    <Col md={6} className="text-left">
                        <button className="btn btn-outline-success my-2 my-sm-0"  onClick={this.handleSubmit.bind(this)} type="submit"> Поиск </button>  
                    </Col>
                </Row>
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
    userPermissions: PropTypes.object.isRequired, 
};
