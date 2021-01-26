import React from "react";
import { Col, Row, } from "react-bootstrap";
import { makeStyles } from "@material-ui/core/styles";
import Card from "@material-ui/core/Card";
import CardContent from "@material-ui/core/CardContent";
import Table from "@material-ui/core/Table";
import TableBody from "@material-ui/core/TableBody";
import TableCell from "@material-ui/core/TableCell";
import TableHead from "@material-ui/core/TableHead";
import TableRow from "@material-ui/core/TableRow";
import Typography from "@material-ui/core/Typography";
import WarningIcon from "@material-ui/icons/Warning";
import { yellow } from "@material-ui/core/colors";
import PropTypes from "prop-types";

import { helpers } from "../common_helpers/helpers.js";

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
    details: {
        alignItems: "center",
    },
    column: {
        flexBasis: "33.33%",
    },
});

export default function CreateCardSourceTelemetryProblemParameters(props) {
    const classes = useStyles();
    const formatter = Intl.DateTimeFormat("ru-Ru", {
        timeZone: "Europe/Moscow",
        day: "numeric",
        month: "numeric",
        year: "numeric",
        hour: "numeric",
        minute: "numeric",
    });

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

    let tele = props.sourceInfo.telemetryParameters,
        memTotal = helpers.changeByteSize(+tele.randomAccessMemory.total*1000),
        memUsed = helpers.changeByteSize(+tele.randomAccessMemory.used*1000),
        memFree = helpers.changeByteSize(+tele.randomAccessMemory.free*1000),
        dateMin = 0,
        dateMax = 0,
        listStorages = [];

    for(let key in tele.timeInterval){
        if(dateMin === 0 || dateMin > tele.timeInterval[key].dateMin){
            dateMin = tele.timeInterval[key].dateMin;
        }

        if(dateMax < tele.timeInterval[key].dateMax){
            dateMax = tele.timeInterval[key].dateMax;
        }

        let timeStorage = ((tele.timeInterval[key].dateMax - tele.timeInterval[key].dateMin) / 86400000).toFixed(1);
        let classMax = "";
        if(((+new Date - dateMax) / 3600000) > 12){
            classMax = "text-danger";
        }

        listStorages.push(<TableRow key={`key_dir_name_${key}`}>
            <TableCell>{key}</TableCell>
            <TableCell><i>{formatter.format(tele.timeInterval[key].dateMin)}</i></TableCell>
            <TableCell>
                <span className={classMax}>
                    <i>{formatter.format(tele.timeInterval[key].dateMax)}</i>
                </span>
            </TableCell>
            <TableCell align="right">{timeStorage}</TableCell>
        </TableRow>);
    }

    let dateTimeBegin = formatter.format(dateMin),
        dateTimeEnd = formatter.format(dateMax),
        timeStorageFiles = ((dateMax - dateMin) / 86400000).toFixed(1),
        behindCurrentTime = ((+new Date) <= dateMax) ? 0.0: (+new Date - dateMax) / 3600000;

    return (       
        <Card className={classes.root}>
            <CardContent>
                <Row>
                    <Col md={12}>
                        <Typography className={classes.title} color="textSecondary" gutterBottom>
                            {`Источник №${props.sourceInfo.sourceID} (${props.sourceInfo.shortSourceName})`}
                            <WarningIcon className="mt-n1" style={{ color: yellow[700] }} fontSize="small" />
                        </Typography>
                    </Col>
                </Row>
                <Row>
                    <Col md={12} className="text-left mt-2">
                        <Typography variant="body2" component="p">
                            информация с источника была получена: <i><strong>{formatter.format(props.sourceInfo.timeReceipt)}</strong></i>
                        </Typography>
                    </Col>
                </Row>
                <Row>
                    <Col md={5} className="text-left">
                        <Typography variant="body2" component="p">
                            диапазон хранящихся файлов: <i>{dateTimeBegin}</i> - <i>{dateTimeEnd}</i>
                        </Typography>
                    </Col>
                    <Col md={7} className="text-right">
                        <Typography variant="body2" component="p">
                            локальное время источника: <i>{formatter.format(tele.currentDateTime)}</i>
                        </Typography>
                    </Col>
                </Row>
                <Row>
                    <Col md={5} className="text-left">
                        <Typography variant="body2" component="p">
                            среднее время хранящихся файлов: <strong>{timeStorageFiles}</strong> сут.
                        </Typography>
                    </Col>
                    <Col md={7} className="text-right">
                        <Typography variant="body2" component="p">
                            загрузка центрального процессора: {getLevelColor(+tele.loadCPU)} %
                        </Typography>
                    </Col>
                </Row>
                <Row>
                    <Col md={5} className="text-left">
                        <Typography variant="body2" component="p">
                            отставание файлов от текущего времени: <strong className="text-danger">{behindCurrentTime.toFixed(1)}</strong> ч.
                        </Typography>
                    </Col>
                    <Col md={7} className="text-right">
                        <Typography variant="body2" component="p">
                            оперативная память, всего: <strong>{memTotal.size}</strong> {memTotal.name}, используется: <strong>{memUsed.size}</strong> {memUsed.name}, свободно: <strong>{memFree.size}</strong> {memFree.name}
                        </Typography>
                    </Col>
                </Row>
                <Row>
                    <Col md={12}>
                        <Table size="small" aria-label="a dense table">
                            <TableHead>
                                <TableRow>
                                    <TableCell><strong>директория</strong></TableCell>
                                    <TableCell><strong>время мин.</strong></TableCell>
                                    <TableCell><strong>время макс.</strong></TableCell>
                                    <TableCell align="right" className="align-middle"><strong>сутки</strong></TableCell>
                                </TableRow>
                            </TableHead>
                            <TableBody>{listStorages}</TableBody>
                        </Table>
                    </Col>
                </Row>
            </CardContent>
        </Card>
    );
}

CreateCardSourceTelemetryProblemParameters.propTypes = {
    sourceInfo: PropTypes.object.isRequired,
};