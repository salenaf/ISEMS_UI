import React from "react";
import PropTypes from "prop-types";

export default class GetStatusFiltering extends React.Component {
    constructor(props){
        super(props);
    }

    render (){
        let ts = this.props.status;
    
        if(ts === "wait"){
            return <span className="text-info">готовится к выполнению</span>;
        } else if(ts === "refused"){
            return <span className="text-danger">oтклонена</span>;
        } else if(ts === "execute"){
            return <span className="text-primary">выполняется</span>;
        } else if(ts === "complete"){
            return <span className="text-success">завершена успешно</span>;
        } else if(ts === "stop"){
            return <span className="text-warning">остановлена пользователем</span>;
        } else {
            return <span>ts</span>;
        }
    }
}

GetStatusFiltering.propTypes = {
    status: PropTypes.string
};