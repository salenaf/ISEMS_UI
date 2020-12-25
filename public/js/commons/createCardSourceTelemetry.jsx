import React from "react";
import { Badge, Col, Row, } from "react-bootstrap";
import { makeStyles } from "@material-ui/core/styles";
import Accordion from "@material-ui/core/Accordion";
import AccordionSummary from "@material-ui/core/AccordionSummary";
import Card from "@material-ui/core/Card";
import CardActions from "@material-ui/core/CardActions";
import CardContent from "@material-ui/core/CardContent";
import Button from "@material-ui/core/Button";
import Table from "@material-ui/core/Table";
import TableBody from "@material-ui/core/TableBody";
import TableCell from "@material-ui/core/TableCell";
import TableHead from "@material-ui/core/TableHead";
import TableRow from "@material-ui/core/TableRow";
import Typography from "@material-ui/core/Typography";
import Skeleton from "@material-ui/lab/Skeleton";
import ExpandMoreIcon from "@material-ui/icons/ExpandMore";
import WarningIcon from "@material-ui/icons/Warning";
import { yellow } from "@material-ui/core/colors";
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
    details: {
        alignItems: "center",
    },
    column: {
        flexBasis: "33.33%",
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

    const numFormatter = new Intl.NumberFormat("ru");

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

    const commonStoragesSpace = () => {
        let storageTimeInterval = props.sourceInfo.informationTelemetry.timeInterval;
        let dateMin = 0;
        let dateMax = 0;

        for(let key in storageTimeInterval){
            if(dateMin === 0 || dateMin > storageTimeInterval[key].dateMin){
                dateMin = storageTimeInterval[key].dateMin;
            }

            if(dateMax < storageTimeInterval[key].dateMax){
                dateMax = storageTimeInterval[key].dateMax;
            }
        }

        let dateTimeBegin = formatter.format(dateMin);
        let dateTimeEnd = formatter.format(dateMax);
        let timeStorageFiles = ((dateMax - dateMin) / 86400000).toFixed(1);
        let behindCurrentTime = ((+new Date) <= dateMax) ? 0.0: (+new Date - dateMax) / 3600000;

        let iconWarning = "";
        let behindCurrentTimeColor = ""; 
        
        if(behindCurrentTime > 12) {
            iconWarning = <WarningIcon className="mt-n1" style={{ color: yellow[700] }} fontSize="small" />;
            behindCurrentTimeColor = "text-danger";
        }

        return (
            <React.Fragment>
                <Row>
                    <Col md={12} className="text-left mt-2">
                        <Typography variant="body2" component="p">
                            временной диапазон хранящихся файлов: с <i>{dateTimeBegin}</i> по <i>{dateTimeEnd}</i>
                        </Typography>
                    </Col>
                </Row>
                <Row>
                    <Col md={12} className="text-left">
                        <Typography variant="body2" component="p">
                            среднее время хранящихся файлов: <strong>{timeStorageFiles}</strong> сут.
                        </Typography>
                    </Col>
                </Row>
                <Row>
                    <Col md={12} className="text-left  mb-2">
                        <Typography variant="body2" component="p">
                            отставание от текущего времени: <strong className={behindCurrentTimeColor}>{behindCurrentTime.toFixed(1)}</strong> ч. {iconWarning}
                        </Typography>
                    </Col>
                </Row>
            </React.Fragment>
        );
    };

    const createStoragesDiskSpace = () => {
        let storageTimeInterval = props.sourceInfo.informationTelemetry.timeInterval;
        let dateMin = 0;
        let dateMax = 0;
        let listStorages = [];

        for(let key in storageTimeInterval){
            if(dateMin === 0 || dateMin > storageTimeInterval[key].dateMin){
                dateMin = storageTimeInterval[key].dateMin;
            }

            if(dateMax < storageTimeInterval[key].dateMax){
                dateMax = storageTimeInterval[key].dateMax;
            }

            let timeStorage = ((storageTimeInterval[key].dateMax - storageTimeInterval[key].dateMin) / 86400000).toFixed(1);

            listStorages.push(<TableRow key={`key_dir_name_${key}`}>
                <TableCell>{key}</TableCell>
                <TableCell><i>{formatter.format(storageTimeInterval[key].dateMin)}</i></TableCell>
                <TableCell><i>{formatter.format(storageTimeInterval[key].dateMax)}</i></TableCell>
                <TableCell align="right">{timeStorage}</TableCell>
            </TableRow>);
        }
        
        return (
            <Accordion>
                <AccordionSummary
                    expandIcon={<ExpandMoreIcon />}
                    aria-controls="panel1c-content"
                    id="panel1c-header" >                               
                    <Typography variant="body2">локальное хранилище</Typography>
                </AccordionSummary>
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
            </Accordion>
        );
    };

    const createLocalDiskSpace = () => {
        let list = props.sourceInfo.informationTelemetry.diskSpace.map((item) => {
            let used = parseInt(item.used, 10);

            return (<TableRow key={`key_disk_name_${item.diskName}`}>
                <TableCell>{item.diskName}</TableCell>
                <TableCell>{item.mounted}</TableCell>
                <TableCell align="right">{item.maxSpace}</TableCell>
                <TableCell align="right">{getLevelColor(used)} %</TableCell>    
            </TableRow>);
        });

        return (
            <Accordion>
                <AccordionSummary
                    expandIcon={<ExpandMoreIcon />}
                    aria-controls="panel1c-content"
                    id="panel1c-header" >                               
                    <Typography variant="body2">локальные жесткие диски</Typography>
                </AccordionSummary>
                <Table size="small" aria-label="a dense table">
                    <TableHead>
                        <TableRow>
                            <TableCell><strong>имя</strong></TableCell>
                            <TableCell><strong>точка монтирования</strong></TableCell>
                            <TableCell align="right"><strong>размер</strong></TableCell>
                            <TableCell align="right"><strong>занято</strong></TableCell>
                        </TableRow>
                    </TableHead>
                    <TableBody>{list}</TableBody>
                </Table>
            </Accordion>
        );
    };

    const createNetworkIntarface = () => {
        let loadNetwork = props.sourceInfo.informationTelemetry.loadNetwork;

        let list = [];
        for(let ifname in loadNetwork){
            list.push(<Row key={`key_${ifname}`}>
                <Col md={4} className="text-left"><Typography variant="body2">{ifname}</Typography></Col>
                <Col md={4} className="text-left"><Typography variant="body2">RX: {numFormatter.format(loadNetwork[ifname].RX)} Кбит</Typography></Col>
                <Col md={4} className="text-left"><Typography variant="body2">TX: {numFormatter.format(loadNetwork[ifname].TX)} Кбит</Typography></Col>
            </Row>);
        }

        return (
            <Accordion>
                <AccordionSummary
                    expandIcon={<ExpandMoreIcon />}
                    aria-controls="panel1c-content"
                    id="panel1c-header" >
                    <Typography variant="body2">сетевые соединения</Typography>
                </AccordionSummary>
                <Row>
                    <Col md={12} className="ml-2 mr-2 mb-2">{list}</Col>
                </Row>
            </Accordion>
        );
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
                            ЦП: {getLevelColor(+tele.loadCPU)} %
                        </Typography>
                    </Col>
                    <Col className="text-right" md={10}>
                        <Typography variant="body2" component="p">
                            оперативная память, всего: <strong>{memTotal.size}</strong> {memTotal.name}, используется: <strong>{memUsed.size}</strong> {memUsed.name}, свободно: <strong>{memFree.size}</strong> {memFree.name}
                        </Typography>
                    </Col>
                </Row>
                <Row>
                    <Col md={6}>{commonStoragesSpace()}</Col>
                    <Col md={6} className="mt-3">{createStoragesDiskSpace()}</Col>
                </Row>
                <Row className="mt-2">
                    <Col md={7}>{createLocalDiskSpace()}</Col>
                    <Col md={5}>{createNetworkIntarface()}</Col>
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
                    <Skeleton animation="wave" height={180} width="100%" style={{ marginBottom: 6 }} /> 
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
