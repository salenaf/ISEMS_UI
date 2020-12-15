import React from "react";
import { Badge, Col, Row, } from "react-bootstrap";
import { makeStyles } from "@material-ui/core/styles";
//import Accordion from '@material-ui/core/Accordion';
import Card from "@material-ui/core/Card";
import CardActions from "@material-ui/core/CardActions";
import CardContent from "@material-ui/core/CardContent";
import Button from "@material-ui/core/Button";
import Typography from "@material-ui/core/Typography";
import Skeleton from "@material-ui/lab/Skeleton";
import PropTypes from "prop-types";

import {helpers} from "../common_helpers/helpers.js";

const useStyles = makeStyles({
    root: {
        minWidth: 275,
    },
    bullet: {
        display: "inline-block",
        margin: "0 2px",
        transform: "scale(0.8)",
    },
    title: {
        fontSize: 14,
    },
    pos: {
        marginBottom: 12,
    },
});

export default function CreateCardSourceTelemetry(props) {
    const classes = useStyles();

    const formatter = Intl.DateTimeFormat("ru-Ru", {
        timeZone: "Europe/Moscow",
        day: "numeric",
        month: "numeric",
        year: "numeric",
        hour: "numeric",
        minute: "numeric",
    });

    const handleClose = function(sid, e) {
        props.handleClose(sid);
    };

    const createSourceLocatTime = () => {
        if(props.sourceInfo.informationTelemetry === null){
            return <Col md={6}></Col>;
        }

        return (
            <Col md={6} className="text-right">
                <Typography variant="body2" component="p">
                        локальное время источника: <i>{formatter.format(props.sourceInfo.informationTelemetry.currentDateTime)}</i>
                </Typography>
            </Col>
        );
    };

    const getLevelColor = (int) => {
        if(int <= 25){
            return <span className="text-success">{int}</span>;
        } else if(int > 25 && int <= 50){
            return <span className="text-info">{int}</span>;
        } else if(int > 50 && int < 75){
            return <span className="text-warning">{int}</span>;
        } else {
            return <span className="text-danger">{int}</span>;
        }
    };

    const createLocalDiskSpace = () => {
        return null;
    };

    const createNetworkIntarface = () => {
        return null;
    };

    const createCardBody = () => {
        if(props.sourceInfo.informationTelemetry === null){
            return;
        }

        let tele = props.sourceInfo.informationTelemetry;
        let memTotal = helpers.changeByteSize(+tele.randomAccessMemory.total*1000);
        let memUsed = helpers.changeByteSize(+tele.randomAccessMemory.used*1000);
        let memFree = helpers.changeByteSize(+tele.randomAccessMemory.free*1000);

        return (
            <React.Fragment>
                <Row>
                    <Col className="text-left" md={2}>
                        <Typography variant="body2" component="p">
                            ЦП: {getLevelColor(+tele.loadCPU)}%
                        </Typography>
                    </Col>
                    <Col className="text-right" md={10}>
                        <Typography variant="body2" component="p">
                            оперативная память, всего: <strong>{memTotal.size}</strong> {memTotal.name}, используется: <strong>{memUsed.size}</strong> {memUsed.name}, свободно: <strong>{memFree.size}</strong> {memFree.name}
                        </Typography>
                    </Col>
                </Row>
                <Row>
                    <Col md={6}>{createLocalDiskSpace()}</Col>
                    <Col md={6}>{createNetworkIntarface()}</Col>
                </Row>
                <Row className="mt-4">
                    <Col md={12} className="text-center">
                        <Typography variant="body2" component="p">
                            {JSON.stringify(tele)}
                        </Typography>
                    </Col>
                </Row>
            </React.Fragment>
        );
    };

    return (
        <Card className={classes.root}>
            <CardContent>
                <Typography className={classes.title} color="textSecondary" gutterBottom>
                    {`Источник №${props.sourceID} (${props.sourceShortName})`}
                </Typography>
                {(!props.sourceInfo.status) ?
                    <Skeleton animation="wave" height={150} width="100%" style={{ marginBottom: 6 }} /> 
                    :
                    <React.Fragment>
                        <Row>
                            <Col md={6} className="text-left">
                                <Typography variant="body2" component="p">
                                    статус сетевого соединения: {(props.sourceInfo.connectionStatus) ? <Badge variant="success">подключен</Badge>: <Badge variant="danger">соединение отсутствует</Badge>}
                                </Typography>
                            </Col>
                            {createSourceLocatTime()}
                        </Row>
                        {createCardBody()}
                    </React.Fragment>}
            </CardContent>
            <CardActions>
                <Button 
                    size="small"
                    onClick={handleClose.bind(null, props.sourceID)}>
                    закрыть
                </Button>
            </CardActions>
        </Card>
    );
}

CreateCardSourceTelemetry.propTypes = {
    sourceID: PropTypes.string.isRequired,
    sourceInfo: PropTypes.object.isRequired,
    sourceShortName: PropTypes.string.isRequired,
    handleClose: PropTypes.func.isRequired,
};
