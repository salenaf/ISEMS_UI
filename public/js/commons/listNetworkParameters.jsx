import React from "react";
import PropTypes from "prop-types";


export default class ListNetworkParameters extends React.Component {
    constructor(props){
        super(props);

        this.getListDirection = this.getListDirection.bind(this);
    }

    getListDirection(d){
        if(this.props.item[d].length === 0){
            return { value: "", success: false };
        }
    
        let result = this.props.item[d].map((item) => {
            if(d === "src"){
                return (<div className="ml-4" key={`elem_${this.props.type}_${d}_${item}`}>
                    <small>{item}</small>
                </div>); 
            }
            if(d === "dst"){
                return (<div className="ml-4" key={`elem_${this.props.type}_${d}_${item}`}>
                    <small>{item}</small>
                </div>); 
            }
    
            return (<div className="ml-4" key={`elem_${this.props.type}_${d}_${item}`}>
                <small>{item}</small>
            </div>); 
        });
    
        return { value: result, success: true };
    }

    render(){
        let resultAny = this.getListDirection("any");
        let resultSrc = this.getListDirection("src");
        let resultDst = this.getListDirection("dst");

        return (
            <React.Fragment>
                {(resultAny.success) ? <div><small className="text-info">any&#8596; </small></div> : ""}
                <div className="text-left">{resultAny.value}</div>
                {(resultSrc.success) ? <div><small className="text-info">src&#8592; </small></div> : ""}
                <div className="text-left">{resultSrc.value}</div>
                {(resultDst.success) ? <div><small className="text-info">dst&#8594; </small></div> : ""}
                <div className="text-left">{resultDst.value}</div>
            </React.Fragment>
        );
    }
} 

ListNetworkParameters.propTypes = {
    type: PropTypes.string.isRequired,
    item: PropTypes.object.isRequired,
};