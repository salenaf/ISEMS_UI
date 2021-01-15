import React from "react";
import Stepper from "@material-ui/core/Stepper";
import Step from "@material-ui/core/Step";
import StepLabel from "@material-ui/core/StepLabel";
import PropTypes from "prop-types";

export default function CreateSteppersTemplateLog(props) {
    if(!props.show){
        return null;
    }

    return (
        <Stepper activeStep={props.activeStep} nonLinear alternativeLabel>
            {props.steppers.map((label, key) => {
                let stepProps = {};
                let labelProps = {};

                stepProps.completed = false;

                if(props.stepsComplete.includes(key)) {
                    stepProps.completed = true;
                }

                if(props.stepsError.includes(key)){
                    labelProps.error = true;
                }

                return (<Step key={label} {...stepProps}>
                    <StepLabel {...labelProps}>{label}</StepLabel>
                </Step>);
            })}
        </Stepper>
    );
}

CreateSteppersTemplateLog.propTypes = {
    show: PropTypes.bool.isRequired,
    steppers: PropTypes.array.isRequired,
    activeStep: PropTypes.number.isRequired,
    stepsError: PropTypes.array.isRequired,
    stepsComplete: PropTypes.array.isRequired,
};
