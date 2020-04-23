import React from "react";
import ReactDOM from "react-dom";
//import { Alert, Card, Spinner, Button, Tab, Tabs } from "react-bootstrap";
import PropTypes from "prop-types";

class PageManagingAnalytics extends React.Component {
    constructor(props){
        super(props);

        this.state ={
            file:null
        };
        this.onFormSubmit = this.onFormSubmit.bind(this);
        this.onChange = this.onChange.bind(this);
        this.fileUpload = this.fileUpload.bind(this);
    }
    onFormSubmit(e){
        e.preventDefault(); // Stop form submit
        this.fileUpload(this.state.file);
    }
    onChange(e) {
        this.setState({file:e.target.files[0]});
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
        });
    }

    render(){
        return (
            <form onSubmit={this.onFormSubmit}>
                <h1>File Upload</h1>
                <input type="file" onChange={this.onChange} />
                <button type="submit">Upload</button>
            </form>
        );
    }
}

PageManagingAnalytics.propTypes = {
    ss: PropTypes.func.isRequired,
    socketIo: PropTypes.object.isRequired,
}; 

ReactDOM.render(<PageManagingAnalytics
    ss={ss}
    socketIo={socket} />, document.getElementById("main-page-content"));
