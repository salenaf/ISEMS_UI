'use strict';

import React from 'react'
import ReactDOM from 'react-dom'

class CreateTable extends React.Component {
    constructor(props) {
        super(props);
    }

    render() {
        return (
            <div>
                <p>Test element!!!</p>
            </div>
        );
    }
}

ReactDOM.render(<CreateTable allInformation={information} />,
    document.getElementById('field_information'));

(function () { })();