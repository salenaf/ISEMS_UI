import React from "react";
import Slider from "@material-ui/core/Slider";

import PropTypes from "prop-types";

export default function RangeSlider(props) {
    const marks = [
        {
            value: 0,
            label: "0",
        },
        {
            value: 6,
            label: "6 часов",
        },
        {
            value: 12,
            label: "12 часов",
        },
        {
            value: 18,
            label: "18 часов",
        },
        {
            value: 24,
            label: "24",
        },
    ];    

    return (
        <Slider
            value={[props.minHour, props.maxHour]}
            onChange={props.handlerChangeRangeSlider}
            min={0}
            max={24}
            step={1}
            marks={marks}
            valueLabelDisplay="auto"
            aria-labelledby="range-slider" />
    );
}

RangeSlider.propTypes = {
    minHour: PropTypes.number.isRequired,
    maxHour: PropTypes.number.isRequired,
    handlerChangeRangeSlider: PropTypes.func.isRequired
};