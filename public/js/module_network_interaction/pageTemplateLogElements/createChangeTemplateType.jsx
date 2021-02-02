import React from "react";
import Radio from "@material-ui/core/Radio";
import RadioGroup from "@material-ui/core/RadioGroup";
import FormControlLabelUI from "@material-ui/core/FormControlLabel";

import PropTypes from "prop-types";

export default function CreateChangeTemplateType(props){
    return (
        <RadioGroup 
            aria-label="gender" 
            name="templateType" 
            value={props.templateType} 
            onChange={props.handlerChangeTemplateType}>
            <FormControlLabelUI className="mb-n2" value="telemetry" control={<Radio color="primary" size="small" />} label="телеметрия" />
            <FormControlLabelUI value="filtration" control={<Radio color="primary" size="small" />} label="фильтрация" />
        </RadioGroup>
    );
}

CreateChangeTemplateType.propTypes = {
    templateType: PropTypes.string.isRequired,
    handlerChangeTemplateType: PropTypes.func.isRequired,
};