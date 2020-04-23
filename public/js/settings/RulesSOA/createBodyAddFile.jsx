import React from "react";
import { Button, Badge, Card, Col, Form, Row } from "react-bootstrap";
import PropTypes from "prop-types";

//import fs from "fs.realpath";

/*//import ModalWindowAddEntity from "../../modalwindows/modalWindowAddEntity.jsx";
class AddZone extends React.Component {
    constructor(props){
        super(props);

        this.handleFileSelect = this. handleFileSelect.bind(this);
        this.handleDragOver= this. handleDragOver.bind(this);
        //this.createZone = this.createZone.bind(this);
    }
    handleFileSelect(evt) {
        evt.stopPropagation();
        evt.preventDefault();
    
        var files = evt.dataTransfer.files; // FileList object.
    
        // files is a FileList of File objects. List some properties.
        var output = [];
        for (var i = 0, f; f = files[i]; i++) {
          output.push('<li><strong>', escape(f.name), '</strong> (', f.type || 'n/a', ') - ',
                      f.size, ' bytes, last modified: ',
                      f.lastModifiedDate.toLocaleDateString(), '</li>');
        }
        document.getElementById('list').innerHTML = '<ul>' + output.join('') + '</ul>';
      }
    
      handleDragOver (evt) {
        evt.stopPropagation();
        evt.preventDefault();
        evt.dataTransfer.dropEffect = 'copy'; // Explicitly show this is a copy.
      }

      componentDidUpdate (){
        this.dropZone = document.getElementById('drop_zone');
        dropZone.addEventListener('dragover', this.handleDragOver, false);
        dropZone.addEventListener('drop', this.handleFileSelect, false);

      }

    render(){
        return  <div>
                    <div className="AddZone" id="drop_zone">Перетащите файл</div>
                    <output id="list"> Тута</output>
                </div>;
      
    }
}

ButtonSaveNewEntity.propTypes = {
    showButton: PropTypes.bool,
    handler: PropTypes.func.isRequired,
};       

*/
/*         <div className="row">
                    <div className="col-md-12 text-right">
                        <ButtonSaveNewEntity handler={this.sendInfoNewEntity} showButton={this.state.addedNewEntity} />
                    </div>
                </div>
*/      

export default class CreateBodyAddFile extends React.Component {
    constructor(props){
        super(props);

        this.fileInput = React.createRef();
        this.fileList = [];
        this.NumFileList = 0;
        
        this.state = {listFiles: []};

        this.handleDeleteElement = id => {
            this.setState(prevState => ({
                listFiles: prevState.listFiles.filter(el => el.id != id),
            }));
                              
            this.fileList[id]="";
            console.log(`1. ${id}; `);      
            //console.log(`2. ${elem.name}; `);
            //this.fileList
        };
        
        this.renderListFile = this.renderListFile.bind(this);
        this.addList        = this.addList.bind(this);
        this.outPutList     = this.outPutList.bind(this);
        this.fileUpload     = this.fileUpload.bind(this);
    }
    /*  let updateObj = this.state;
        updateObj.listFiles.push(testStr1);
        this.setState(updateObj);
        alert(JSON.stringify(this.state));*/
    
    addList(event) {
        // highlight-range{4}
        event.preventDefault();
        
        let updateObj = this.state; 

        let str="";
        // if()
        let i=this.NumFileList;
        
        /*if(this.fileList[0]!=undefined){ 
            i= this.fileList[this.fileList.length-1].id + 1 ;}*/
    
        let j=0;
        let fileName = null;
        let checkIp = null;
        let regul    =  new RegExp(/.+\.rules$/);

        while(this.fileInput.current.files[j]!=undefined){
            fileName = this.fileInput.current.files[j].name;
            checkIp = fileName.match(regul);
            
            if(checkIp!=null){
                let fileOne = { id: i,
                    name: `${this.fileInput.current.files[j].name}`,
                    type: `${this.fileInput.current.files[j].type}`,
                    size: `${this.fileInput.current.files[j].size}`,
                    file: this.fileInput.current.files[j],
                    lastModifiedDate: `${this.fileInput.current.files[j].lastModifiedDate.toLocaleDateString()}`,
                };
                this.fileList[i]= fileOne;
            
                str += fileOne.name + ", ";
                updateObj.listFiles.push(fileOne);
            
                i++;
            } 
            j++;
        }
        //let output = [];
        this.NumFileList = i--;
        
        this.setState(updateObj);
        //alert(`что ввелось: ${str}`);
    }
    /* <strong> {`${this.fileInput.current.files[j].name}:`}</strong>
    {` ${this.fileInput.current.files[j].type}, ${this.fileInput.current.files[j].size} байт`} 
    className="table table-sm"*/
    
    // ---------------------------- Загрузка файлов из списка (в папочку uploads)---------------------------
    renderListFile(){
        let updateObj = this.state;
        // updateObj.listFiles.push(testStr1);
        this.setState(updateObj);

        let str = "";
        for(let i = 0; i< this.fileList.length; i++){
            if(this.fileList[i].name != undefined){  
                str += this.fileList[i].name + "; " ;
                this.fileUpload(this.fileList[i].file); 
            } 
        }
        
        alert(`Итог: ${str}`); 
        // console.log();

    }

    fileUpload(file){
        console.log("upload file");
        console.log(file);

        let stream = this.props.ss.createStream();

        this.props.ss(this.props.socketIo).emit("uploading files with SOA rules", stream, { name: file.name, size: file.size });
        let blobStream = this.props.ss.createBlobReadStream(file);
        //let size = 0;
        blobStream.pipe(stream);
        blobStream.on("data", function(chunk) {
            console.log(chunk);

            /*            size += chunk.length;
            let percent = (Math.floor(size / file.size * 100) + "%");
            let divProgressBar = document.querySelector("#modalProgressBar .progress-bar");
            divProgressBar.setAttribute("aria-valuenow", percent);
            divProgressBar.style.width = percent;
            divProgressBar.innerHTML = percent;

            if (file.size === size) $("#modalProgressBar").modal("hide");
            */
        });
    }

    outPutList(){
        const { listFiles } = this.state;
        if(this.fileInput.current==undefined) return;
        let outPutTabl =    <React.Fragment>
            <table className="table table-sm">
                <thead>
                    <tr>
                        <th> Название </th><th> Тип файла </th>{/*<th> Размер файла </th>*/}<th> </th>
                    </tr>
                </thead>
                <tbody>
                    {listFiles.map(el => (
                        <tr key={el.id} >
                            <td> {el.name} </td> 
                            {/*<td> .rules </td>*/}
                            <td> {el.size}  байт </td>
                            <td>  
                                <button type="button" className="close" onClick={() => { this.handleDeleteElement(el.id); }} aria-label="Close"> 
                                    <span aria-hidden="true">&times;</span>
                                </button> 
                            </td>  
                        </tr>
                    ))}
                </tbody>
            </table>
        </React.Fragment>;
        return outPutTabl;
    }    

    /*  <ul>
        {listFiles.map(el => (
            <li key={el.id} >
                {el.title}
                                        
                <button type="button" className="close" onClick={() => { this.handleDeleteElement(el.id) }} aria-label="Close"> 
                    <span aria-hidden="true">&times;</span>
                </button> 
            </li>))
            }   
            {this.renderListFile()this.state.listFiles}
    </ul>*/
    /*
        <div className="input-group mb-3">
            <input className="form-control-file border" type="file" onChange={this.addList.bind(this)} ref={this.fileInput}  id="files" name="files[]" multiple />
            <output id="list"></output>
        </div>
    
    */
    render(){ 
        const { listFiles} = this.state;
        return (
            <React.Fragment>
                <label> Выберите файл </label>
                <form onSubmit={this.handleSubmit}>
                    <div className="custom-file">
                        <input type="file" className="custom-file-input" type="file" onChange={this.addList.bind(this)} ref={this.fileInput}  id="files" name="files[]" multiple />
                        <label className="custom-file-label">Открыть файл</label>
                    </div>
                </form> 
                <br/>
                {this.outPutList()}
                <br/>  
                <button className="btn btn-outline-success float-right" onClick={this.renderListFile.bind(this)} type="button">Добавить</button>
            </React.Fragment>
        );
    }
}

CreateBodyAddFile.propTypes ={
    ss: PropTypes.func.isRequired,
    socketIo: PropTypes.object.isRequired,
    listSourcesInformation: PropTypes.object.isRequired,
};