import React from "react";
import { makeStyles } from "@material-ui/core/styles";
import Chip from "@material-ui/core/Chip";
import Paper from "@material-ui/core/Paper";
import Close from "@material-ui/icons/Close";
import PropTypes from "prop-types";

const useStyles = makeStyles((theme) => ({
    root: {
        display: "flex",
        justifyContent: "center",
        flexWrap: "wrap",
        listStyle: "none",
        padding: theme.spacing(0.5),
        margin: 0,
    },
    chip: {
        margin: theme.spacing(0.5),
    },
}));

export default function CreateChip(props) {
    const classes = useStyles();

    return (
        <Paper component="ul" className={classes.root}>
            {props.chipData.map((sid) => {
                console.log(sid);
               
                return (
                    <li key={`key_sid_${sid}`}>
                        <Chip
                            icon={<Close fontSize="large" />}
                            label={sid}
                            onDelete={props.handleDelete(sid)}
                            className={classes.chip}
                        />
                    </li>
                );
            })}
        </Paper>
    );
}

CreateChip.propTypes = {
    chipData: PropTypes.array.isRequired,
    handleDelete: PropTypes.func.isRequired,
};
