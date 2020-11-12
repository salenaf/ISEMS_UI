import React from "react";
import { ProgressBar } from "react-bootstrap";
import PropTypes, { object } from "prop-types";
import { data } from "jquery";
import { relativeTimeRounding } from "moment";
import { timeout } from "async";

/* 
 * Body Add File
 * 
*/

export default class CreateBodyAddFile extends React.Component {
    constructor(props){
        super(props);

        this.fileInput = React.createRef();
        this.listFileName = [];
        this.NumFileList = 0;
        this.state = {
            outputList_state: [],
            loadProcess: -1,
            //outPutList: this.outPutList.call(this),
        };

        this.handleDeleteElement = name => {
            this.setState(prevState => ({
                outputList_state: prevState.outputList_state.filter(el => el.name != name),
            }));
            //delete this.listFileName[this.listFileName.indexOf(name)];
            this.listFileName = this.listFileName.filter(el => el != name);
            //console.log(`1. ${name}; `);      
        };
        
        this.renderListFile = this.renderListFile.bind(this);
        this.addList        = this.addList.bind(this);
        this.outPutList     = this.outPutList.bind(this);
        this.fileUpload     = this.fileUpload.bind(this);
        this.funProgressBar = this.funProgressBar.bind(this);
    }
        // componentDidMount(){
        //     console.log("-------");
        //     console.log(document.getElementById("files").files);
        //     console.log("-------");
        // }
        
        //let updateObj = this.state; 
        // let updateObj = Object.assign({}, this.state);
        // this.setState(updateObj);

        // let updateObj = Object.assign([], this.state.outputList_state);
        // this.setState({ Array: updateObj });
       // let updateObj = this.state.outputList_state;
    addList(event) {
        event.preventDefault();
        let updateObj = Object.assign([], this.state.outputList_state);

        //let i=this.NumFileList; ///////// <-------------------- ????????????
    
        let j=0;
        let fileName = null;
        let checkIp = null;
        let regul    =  new RegExp(/.+\.rules$/);
//let arr = [];
        while(this.fileInput.current.files[j]!=undefined){
            fileName = this.fileInput.current.files[j].name;
            checkIp = fileName.match(regul);
            
            if(checkIp!=null){
                let fileOne = { 
                   // id: i,                                              ///////// <-------------------- ????????????
                    name: `${this.fileInput.current.files[j].name}`,
                    type: `${this.fileInput.current.files[j].type}`,
                    size: `${this.fileInput.current.files[j].size}`,
                    file: this.fileInput.current.files[j],
                    lastModifiedDate: `${this.fileInput.current.files[j].lastModifiedDate.toLocaleDateString()}`,
                };
               
                if(!this.listFileName.includes(fileOne.name)){
                 //   console.log(`i = ${i}, obj = ${fileOne}`);  
                    updateObj.push(fileOne); 
                    
                    this.listFileName.push(fileOne.name);                         
                    //arr.push(fileOne);                                // str += fileOne.name + ", ";
                  //  i++;                                                 ///////// <-------------------- ????????????       
                }
            } 
            j++;
        }
        //let output = [];
       // this.NumFileList = i--; ///////// <-------------------- ????????????
        
        //this.setState(updateObj);

        this.setState({ outputList_state: updateObj });

    }
   
   // ---------------------------- Загрузка файлов из списка (в папочку uploads)---------------------------
    renderListFile(){
        //let updateObj = this.state;
        // updateObj.outputList_state.push(testStr1);
        //this.setState(updateObj);
        let files = [];
        let str = "";

        console.log(`Список имён  ${this.listFileName.length}`);
        console.log(this.listFileName);

        let updateObj = Object.assign([], this.state.outputList_state);
        console.log(`В статусе ${updateObj.length}`);
        console.log(this.state.outputList_state);

        for(let i = 0; i< this.listFileName.length; i++){
                str += this.listFileName[i] + "; " ;
                files.push(updateObj[i].file);
        }
        let count = 0;
        let doli = files.length;
        let verification = confirm(`Загрузить выбранные файлы? (${str})`); 
        if(verification){
              for(let i = 0; i< files.length; i++){
                if(files[i].name != undefined){  
                    this.fileUpload(files[i], (data) =>{
                        count++;
                        if(count != doli){
                            this.setState({ loadProcess: count/doli*100 });
                          }else{
                            this.setState({ loadProcess: 100 });
                            setTimeout(
                                () => {
                                    this.setState({ loadProcess: -1 });
                                },
                                1 * 1000
                            );
                            setTimeout(
                                () => {
                                    window.location.reload();
                                },
                                2 * 1000
                            );

                          }
                        console.log(`Загружен ${data}`);
                        this.handleDeleteElement(data);
                    });             
                }
            }
        
        
        }
        return progressBar;
        // console.log();
    }

    funProgressBar(){
        let progressBar = <div></div>;
        if(this.state.loadProcess!=-1)
            progressBar = <ProgressBar animated now={this.state.loadProcess} />;
        return progressBar;
    }

    fileUpload(file, callback){
        // console.log("upload file");
        // console.log(file);
        
        let stream = this.props.ss.createStream();
        this.props.ss(this.props.socketIo).emit("uploading files with SOA rules", stream, { name: file.name, size: file.size }); //list: listFile}); 
        let blobStream = this.props.ss.createBlobReadStream(file);
        let size = 0;
        blobStream.pipe(stream);

        blobStream.on("data", function(chunk) {
            //console.log(chunk);
            size += chunk.length;
            if (file.size === size) { 
                callback(file.name);
            } 
            /*            size += chunk.length;
            let percent = (Math.floor(size / file.size * 100) + "%");
            let divProgressBar = document.querySelector("#modalProgressBar .progress-bar");
            divProgressBar.setAttribute("aria-valuenow", percent);
            divProgressBar.style.width = percent;
            divProgressBar.innerHTML = percent;
            if (file.size === size) $("#modalProgressBar").modal("hide");
            */
        }) ;
        //location.reload();
    }

    outPutList(){
        const { outputList_state } = this.state;

        // console.log("this.fileInput.current---->") ;
        // console.log(this.fileInput.current);
        // console.log(this.fileInput);
        // console.log("this.state.outputList_state----->");
        // console.log(this.state.outputList_state);

       // if(this.fileInput.current==undefined) return;
        if(this.state.outputList_state.length === 0) return;

        let list = outputList_state;
        //console.log(list);
        //if(list == []) return;
        // plan B list.indexOf(el)
        //console.log(`length = ${list.length}`)
let i = 0;
        let outPutTabl =    <React.Fragment>
            <table className="table table-sm">
                <thead>
                    <tr>
                        <th> Название </th><th> Тип файла </th>{/*<th> Размер файла </th>*/}<th> </th>
                    </tr>
                </thead>
                <tbody>
                    {list.map(el => (
                        <tr key={el.name} >
                            <td> {el.name} </td> 
                            {/*<td> .rules </td>*/}
                            <td> {el.size}  байт </td>
                            <td>  
                                <button type="button" className="close" onClick={() => { this.handleDeleteElement(el.name); }} aria-label="Close"> 
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
        {outputList_state.map(el => (
            <li key={el.id} >
                {el.title}
                                        
                <button type="button" className="close" onClick={() => { this.handleDeleteElement(el.id) }} aria-label="Close"> 
                    <span aria-hidden="true">&times;</span>
                </button> 
            </li>))
            }   
            {this.renderListFile()this.state.outputList_state}
    </ul>*/
    /*
        <div className="input-group mb-3">
            <input className="form-control-file border" type="file" onChange={this.addList.bind(this)} ref={this.fileInput}  id="files" name="files[]" multiple />
            <output id="list"></output>
        </div>
    
    */
    render(){ 
       // const { outputList_state} = this.state;
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
                {this.funProgressBar()}
                <br/>  
                <button className="btn btn-outline-success float-right" onClick={this.renderListFile.bind(this)} type="button">Добавить</button>

            </React.Fragment>
        );
    }
}

CreateBodyAddFile.propTypes = {
    ss: PropTypes.func.isRequired,
    socketIo: PropTypes.object.isRequired,
    userPermissions: PropTypes.object.isRequired,
    //listSourcesInformation: PropTypes.object.isRequired,
};