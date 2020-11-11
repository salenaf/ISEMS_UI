import { InlineDateTimePicker } from "material-ui-pickers";
import React, { Fragment, useState } from "react";

class CreateDateTimePicker extends React.Component {
    constructor(props){
        super(props);
    }

    render(){
        const [selectedDate, handleDateChange] = useState(new Date());
        /**
 * format={this.props.getFormatString({
                            moment: "YYYY/MM/DD hh:mm A",
                            dateFns: "yyyy/MM/dd HH:mm",
                        })}
 */
        return (
            <Fragment>
                <div className="picker">
                    <InlineDateTimePicker
                        label="Basic example"
                        value={selectedDate}
                        onChange={handleDateChange}
                    />
                </div>
    
                <div className="picker">
                    <InlineDateTimePicker
                        keyboard
                        ampm={false}
                        label="With keyboard"
                        value={selectedDate}
                        onChange={handleDateChange}
                        onError={console.log}
                        disablePast
                        
                        mask={[
                            /\d/,
                            /\d/,
                            /\d/,
                            /\d/,
                            "/",
                            /\d/,
                            /\d/,
                            "/",
                            /\d/,
                            /\d/,
                            " ",
                            /\d/,
                            /\d/,
                            ":",
                            /\d/,
                            /\d/,
                        ]}
                    />
                </div>
            </Fragment>
        );
    }
}

export default CreateDateTimePicker;