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

    console.log("CreateCardSourceTelemetryProblemParameters");

    const formatter = Intl.DateTimeFormat("ru-Ru", {
        timeZone: "Europe/Moscow",
        day: "numeric",
        month: "numeric",
        year: "numeric",
        hour: "numeric",
        minute: "numeric",
    });
    /*
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
        );
    };
*/
    return (       
        <Card className={classes.root}>
            <CardContent>
                <Typography className={classes.title} color="textSecondary" gutterBottom>
                    {`Источник №${props.sourceInfo.sourceID} (${props.sourceInfo.shortSourceName})`}
                    <strong>Это доделать!! Кроме того для тестов я выключил setInterval в handlerTimerTick, позже необходимо включить</strong>
                </Typography>
            </CardContent>
        </Card>
    );
}

CreateCardSourceTelemetryProblemParameters.propTypes = {
    sourceInfo: PropTypes.object.isRequired,
};