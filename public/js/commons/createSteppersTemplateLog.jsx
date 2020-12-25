import React from "react";
import Stepper from "@material-ui/core/Stepper";
import Step from "@material-ui/core/Step";
import StepLabel from "@material-ui/core/StepLabel";
import { makeStyles } from "@material-ui/core/styles";
import PropTypes from "prop-types";

const useStyles = makeStyles((theme) => ({
    root: {
        width: "100%",
    },
    button: {
        marginRight: theme.spacing(1),
    },
    instructions: {
        marginTop: theme.spacing(1),
        marginBottom: theme.spacing(1),
    },
}));

export default function CreateSteppersTemplateLog(props) {

    console.log("func 'createSteppersTemplateLog'");
    console.log(props);

    const [activeStep, setActiveStep] = React.useState(0);

    return (
        <Stepper activeStep={activeStep} alternativeLabel>
            {props.steppers.map((label) => (
                <Step key={label}>
                    <StepLabel>{label}</StepLabel>
                </Step>
            ))}
        </Stepper>
    );
}

CreateSteppersTemplateLog.propTypes = {
    steppers: PropTypes.array.isRequired,
};
