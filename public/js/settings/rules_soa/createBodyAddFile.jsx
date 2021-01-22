import React from "react";
import { ProgressBar } from "react-bootstrap";
import PropTypes, { object } from "prop-types";
import { data } from "jquery";
import { relativeTimeRounding } from "moment";
import { timeout } from "async";

/* 
 * Загрузка файла(ов) с правилами
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
        };
        this.numberOfFiles = 0;
        this.handleDeleteElement = name => {
            this.setState(prevState => ({
                outputList_state: prevState.outputList_state.filter(el => el.name != name),
            }));
            this.listFileName = this.listFileName.filter(el => el != name);
        };
        
        this.renderListFile = this.renderListFile.bind(this);
        this.addList        = this.addList.bind(this);
        this.outPutList     = this.outPutList.bind(this);
        this.fileUpload     = this.fileUpload.bind(this);
        this.funProgressBar = this.funProgressBar.bind(this);
    }

    addList(event) {
        event.preventDefault();
        let updateArr = Object.assign([], this.state.outputList_state);

        let j=0;
        let fileName = null;
        let checkIp = null;
        let regul    =  new RegExp(/.+\.rules$/);

        while(this.fileInput.current.files[j]!=undefined){
            fileName = this.fileInput.current.files[j].name;
            checkIp = fileName.match(regul);
            
            if(checkIp!=null){
                let fileOne = { 
                    name: `${this.fileInput.current.files[j].name}`,
                    size: `${this.fileInput.current.files[j].size}`,
                    file: this.fileInput.current.files[j],
                    lastModifiedDate: `${this.fileInput.current.files[j].lastModifiedDate.toLocaleDateString()}`,
                };
               
                if(!this.listFileName.includes(fileOne.name)){ 
                    updateArr.push(fileOne); 
                    
                    this.listFileName.push(fileOne.name);                         
                }
            } 
            j++;
        }
        this.setState({ outputList_state: updateArr });
    }
   
    // ---------------------------- Загрузка файлов из списка (в папочку uploads)---------------------------
    renderListFile(){

        let files = [];
        let str = "";

        let updateObj = Object.assign([], this.state.outputList_state);

        for(let i = 0; i< this.listFileName.length; i++){
            str += this.listFileName[i] + "; " ;
            files.push(updateObj[i].file);
        }
        let count = 0;            
        let doli = files.length;
        let numberOfFiles = Math.floor(1/doli * 100 );

        let verification = confirm(`Загрузить выбранные файлы? (${str})`); 
        if(verification){ 
            this.setState({ loadProcess: 1});
            for(let i = 0; i< files.length; i++){
                if(files[i].name != undefined){  
                    this.fileUpload(files[i], numberOfFiles, (data) =>{
                        count++;
                        if(count != doli){
                            this.setState({ loadProcess: Math.floor(count/doli * 100 )});
                        }else{
                            this.setState({ loadProcess: 100 });
                            setTimeout(
                                () => {
                                    this.setState({ loadProcess: -1 });
                                    setTimeout(
                                        () => {
                                            window.location.reload();
                                        },
                                        500
                                    );
                                },
                                1 * 1000
                            );
                        }
                        this.handleDeleteElement(data);
                    });             
                }
            }
        }
    }

    funProgressBar(){
        let progressBar = <div></div>;
        if(this.state.loadProcess!=-1)
            progressBar = <ProgressBar animated now={this.state.loadProcess} />;
        return progressBar;
    }

    fileUpload(file, doli, callback){
        let stream = this.props.ss.createStream();
        this.props.ss(this.props.socketIo).emit("uploading files with SOA rules", stream, { name: file.name, size: file.size }); //list: listFile}); 
        let blobStream = this.props.ss.createBlobReadStream(file);
        let size = 0;
        blobStream.pipe(stream);
        let a =  this.state.loadProcess;
        blobStream.on("data", function(chunk) {
            size += chunk.length;
 
            console.log(`doli ${doli}% `);
            console.log(a);
            let percent = Math.floor(size/ file.size*100 ) ;
            console.log(`1: ${percent}`);

            if (file.size === size) {
                callback(file.name);
            } 
        }) ;
    }

    outPutList(){
        const { outputList_state } = this.state;

        if(this.state.outputList_state.length === 0) return;

        let list = outputList_state;
        let outPutTabl =    <React.Fragment>
            <table className="table table-sm">
                <thead>
                    <tr>
                        <th> Название </th><th> Размер файла </th>{/*<th> Тип файла </th>*/}<th> </th>
                    </tr>
                </thead>
                <tbody>
                    {list.map(el => (
                        <tr key={el.name} >
                            <td> {el.name} </td> 
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

    render(){ 
        return (
            <React.Fragment>
                <label> Выберите файл </label>
                <form onSubmit={this.handleSubmit}>
                    <div className="custom-file">
                        <input type="file" className="custom-file-input" onChange={this.addList.bind(this)} ref={this.fileInput}  id="files" name="files[]" multiple />
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
};