import React from "react";
import PropTypes from "prop-types";

export default class GetStatusDownload extends React.Component {
    constructor(props){
        super(props);
    }

    render (){
        let ts = this.props.status;
    
        if(ts === "wait"){
            return <small className="text-info">готовится к выполнению</small>;
        } else if(ts === "refused"){
            return <small className="text-danger">oтклонена</small>;
        } else if(ts === "execute"){
            return <small className="text-primary">выполняется</small>;       
        } else if(ts === "complete"){
            return <small className="text-success">завершена успешно</small>;       
        } else if(ts === "stop"){
            return <small className="text-warning">остановлена пользователем</small>;
        } else if(ts === "not executed"){
            return <small className="text-light bg-dark">не выполнялась</small>;
        } else {
            return <small>ts</small>;
        }
    }
}

GetStatusDownload.propTypes = {
    status: PropTypes.string
};