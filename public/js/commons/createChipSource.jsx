import React from "react";
import { makeStyles } from "@material-ui/core/styles";
import Chip from "@material-ui/core/Chip";
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

    const handleDelete = (sid) => {
        props.handleDelete(sid);
    };

    if(props.chipData.length === 0){
        return null;
    }

    return (
        props.chipData.map((sid) => {              
            return (
                <Chip
                    key={`key_sid_${sid}`}
                    label={sid}
                    onDelete={handleDelete.bind(null, sid)}
                    variant="outlined"
                    className={classes.chip} />
            );
        })
    );
}

CreateChip.propTypes = {
    chipData: PropTypes.array.isRequired,
    handleDelete: PropTypes.func.isRequired,
};
