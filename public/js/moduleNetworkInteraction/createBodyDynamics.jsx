import React from "react";
import { Alert, Card, ProgressBar, Button, Tab, Tabs } from "react-bootstrap";
import PropTypes from "prop-types";

export default class CreateBodyDynamics extends React.Component {
    constructor(props){
        super(props);
    }

    render(){
        return (
            <React.Fragment>
                {"Динамика выполнения задач"}
                <br/>
                <Card>
                    <Card.Body>
                        Источник №1023 (пример для скачивания файлов)
                        <ProgressBar now="65" label={"65%"} />
                        скачанных/всего файлов: 3/12
                    </Card.Body>
                </Card>
                <br/>
                <Card>
                    <Card.Body>
                        Источник №1052 (пример для фильтрации файлов)
                        <ProgressBar now="78" label={"132/245"} />
                        найдено файлов: 13
                    </Card.Body>
                </Card>
            </React.Fragment>
        );
    }
}

CreateBodyDynamics.propTypes = {

};