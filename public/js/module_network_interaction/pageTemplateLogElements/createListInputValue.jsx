import React from "react";
import { Badge, Col, Row } from "react-bootstrap";

import PropTypes from "prop-types";

export default function ListInputValue(props){
    let isEmpty = true;

    done: 
    for(let et in props.inputValue){
        for(let d in props.inputValue[et]){
            if(props.inputValue[et][d].length > 0){
                isEmpty = false;

                break done;
            }
        }
    }

    if(isEmpty){
        return <React.Fragment></React.Fragment>;
    }

    let getList = (type) => {
        let getListDirection = (d) => {
            if(props.inputValue[type][d].length === 0){
                return { value: "", success: false };
            }

            let result = props.inputValue[type][d].map((item) => {
                if(d === "src"){
                    return <div className="ml-4" key={`elem_${type}_${d}_${item}`}>
                        <small className="text-info">{d}&#8592; </small>{item}
                            &nbsp;<a onClick={props.hendlerDeleteAddedElem.bind(this, {
                            type: type,
                            direction: d,
                            value: item
                        })} className="clickable_icon" href="#"><img src="../images/icons8-delete-16.png"></img></a>
                    </div>; 
                }
                if(d === "dst"){
                    return <div className="ml-4" key={`elem_${type}_${d}_${item}`}>
                        <small className="text-info">{d}&#8594; </small>{item}
                            &nbsp;<a onClick={props.hendlerDeleteAddedElem.bind(this, {
                            type: type,
                            direction: d,
                            value: item
                        })} className="clickable_icon" href="#"><img src="../images/icons8-delete-16.png"></img></a>
                    </div>; 
                }

                return <div className="ml-4" key={`elem_${type}_${d}_${item}`}>
                    <small className="text-info">{d}&#8596; </small>{item}
                        &nbsp;<a onClick={props.hendlerDeleteAddedElem.bind(this, {
                        type: type,
                        direction: d,
                        value: item
                    })} className="clickable_icon" href="#"><img src="../images/icons8-delete-16.png"></img></a>
                </div>; 
            });

            return { value: result, success: true };
        };

        let resultAny = getListDirection("any");
        let resultSrc = getListDirection("src");
        let resultDst = getListDirection("dst");

        return (
            <React.Fragment>
                <div>{resultAny.value}</div>
                {(resultAny.success && (resultSrc.success || resultDst.success)) ? <div className="text-danger text-center">&laquo;ИЛИ&raquo;</div> : <div></div>}                   
                <div>{resultSrc.value}</div>
                {(resultSrc.success && resultDst.success) ? <div className="text-danger text-center">&laquo;И&raquo;</div> : <div></div>}                   
                <div>{resultDst.value}</div>
            </React.Fragment>
        );
    };

    return (
        <React.Fragment>
            <Row>
                <Col sm="3" className="text-center">
                    <Badge variant="dark">ip адрес</Badge>
                </Col>
                <Col sm="1" className="text-danger text-center">&laquo;ИЛИ&raquo;</Col>
                <Col sm="3" className="text-center">
                    <Badge variant="dark">сеть</Badge>
                </Col>
                <Col sm="1" className="text-danger text-center">&laquo;И&raquo;</Col>
                <Col sm="4" className="text-center">
                    <Badge  variant="dark">сетевой порт</Badge>
                </Col>
            </Row>
            <Row>
                <Col sm="4">{getList("ip")}</Col>
                <Col sm="4">{getList("nw")}</Col>
                <Col sm="4">{getList("pt")}</Col>
            </Row>
        </React.Fragment>
    );
}

ListInputValue.propTypes = {
    inputValue: PropTypes.object.isRequired,
    hendlerDeleteAddedElem: PropTypes.func.isRequired,
};