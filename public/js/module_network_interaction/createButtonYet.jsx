import React from "react";
import Button from "@material-ui/core/Button";
import { blue } from "@material-ui/core/colors";
import { makeStyles } from "@material-ui/core/styles";
import CircularProgress from "@material-ui/core/CircularProgress";
import PropTypes from "prop-types";

const useStyles = makeStyles((theme) => ({
    root: {
        display: "flex",
        alignItems: "center",
    },
    wrapper: {
        margin: theme.spacing(1),
        position: "relative",
    },
    buttonProgress: {
        color: blue[500],
        position: "absolute",
        top: "50%",
        left: "50%",
        marginTop: -12,
        marginLeft: -12,
    },
}));

export default function CreateButtonNextChunk(props){
    if(props.countDocument <= props.maxChunkLimit){
        return;
    }

    if(props.countMsgList >= props.countDocument){
        return;
    }

    const classes = useStyles();

    return (
        <div className={classes.root}>
            <div className={classes.wrapper}>
                <Button 
                    size="small" 
                    variant="contained" 
                    onClick={props.handlerNextChunk}
                    disabled={props.buttonNextChunkIsDisabled} >
                        ещё...
                </Button>
                {props.buttonNextChunkIsDisabled && <CircularProgress size={24} className={classes.buttonProgress} />}
            </div>
        </div>
    );
}

CreateButtonNextChunk.propTypes = {
    countMsgList: PropTypes.number.isRequired,
    countDocument: PropTypes.number.isRequired,
    maxChunkLimit: PropTypes.number.isRequired,
    handlerNextChunk: PropTypes.func.isRequired,
    buttonNextChunkIsDisabled: PropTypes.bool.isRequired,
};
