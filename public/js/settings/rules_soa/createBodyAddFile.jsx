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
                   // type: `${this.fileInput.current.files[j].type}`,
                    size: `${this.fileInput.current.files[j].size}`,
                    file: this.fileInput.current.files[j],
                    lastModifiedDate: `${this.fileInput.current.files[j].lastModifiedDate.toLocaleDateString()}`,
                };
               
                if(!this.listFileName.includes(fileOne.name)){
                 //   console.log(`i = ${i}, obj = ${fileOne}`);  
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
        let numberOfFiles = Math.floor(1/doli * 100 );
        //doli = Math.floor(1/doli * 100 );
        console.log(`Doli ${this.numberOfFiles}% `);
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
                                },
                                1 * 1000
                            );
                            setTimeout(
                                () => {
                                   // window.location.reload();
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

    fileUpload(file, doli, callback){
        // console.log("upload file");
        // console.log(file);
        
        let stream = this.props.ss.createStream();
        this.props.ss(this.props.socketIo).emit("uploading files with SOA rules", stream, { name: file.name, size: file.size }); //list: listFile}); 
        let blobStream = this.props.ss.createBlobReadStream(file);
        let size = 0;
        blobStream.pipe(stream);
        let a =  this.state.loadProcess;
        blobStream.on("data", function(chunk) {
            //console.log(chunk);
            size += chunk.length;
 
            console.log(`doli ${doli}% `);
            console.log(a);
            let percent = Math.floor(size/ file.size*100 ) ;
            console.log(`1: ${percent}`);
            //this.setState({ loadProcess: });// Math.floor(count/doli * 100 )

            if (file.size === size) {
                callback(file.name);
            } 

            /*   let divProgressBar = document.querySelector("#modalProgressBar .progress-bar");
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

        if(this.state.outputList_state.length === 0) return;

        let list = outputList_state;
        let i = 0;
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
       // const { outputList_state} = this.state;
        return (
            <React.Fragment>
                <label> Выберите файл </label>
                <p> Не обновляет данные в бд, а только дописывает тех, которых нет </p>
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