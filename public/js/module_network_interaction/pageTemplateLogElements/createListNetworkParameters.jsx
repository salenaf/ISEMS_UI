import React from "react";

import PropTypes from "prop-types";

export default function CreateListNetworkParameters(props) {
    if ((typeof props.inputValue === "undefined") || (typeof props.inputValue[props.type] === "undefined")) {
        return;
    }

    let getListDirection = (d) => {
        if ((props.inputValue[props.type][d] === null) || (props.inputValue[props.type][d].length === 0)) {
            return { value: "", success: false };
        }

        let result = props.inputValue[props.type][d].map((item) => {
            if (d === "src") {
                return item;
            }

            if (d === "dst") {
                return item;
            }

            return item;
        });

        return { value: result, success: true };
    };

    let resultAny = getListDirection("any");
    let resultSrc = getListDirection("src");
    let resultDst = getListDirection("dst");

    let valueString = (valueList) => {
        let s = "";
        let count = valueList.length;

        for (let i = 0; i < count; i++) {
            if (i < count - 1) {
                s += `${valueList[i]}, `;
            } else {
                s += valueList[i];
            }
        }

        return s;
    };

    return ( 
        <React.Fragment>
            <div> {(resultAny.value.length > 0) ? <span className="text-info"> any &#8596; {valueString(resultAny.value)}</span> : ""}</div>
            {(resultAny.success && (resultSrc.success || resultDst.success)) ? <span className="text-danger"> &laquo; <small> ИЛИ </small>&raquo;</span> : ""} 
            <div> {(resultSrc.value.length > 0) ? <span className="text-info"> src &#8592; {valueString(resultSrc.value)}</span> : ""}</div>
            {(resultSrc.success && resultDst.success) ? <span className="text-danger"> &laquo; <small> И </small>&raquo;</span> : ""} 
            <div> {(resultDst.value.length > 0) ? <span className="text-info"> dst &#8594; {valueString(resultDst.value)}</span> : ""}</div>
        </React.Fragment>
    );
}

CreateListNetworkParameters.propTypes = {
    type: PropTypes.string.isRequired,
    inputValue: PropTypes.object.isRequired,
};