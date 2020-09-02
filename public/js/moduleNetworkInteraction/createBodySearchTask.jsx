import React from "react";
import { Button, Card, Col, Form, Row, FormControl, InputGroup } from "react-bootstrap";
import PropTypes from "prop-types";

import DatePicker from "react-datepicker";
import TokenInput from "react-customize-token-input";

class CreateProtocolList extends React.Component {
    constructor(props){
        super(props);
    }

    render(){
        return (
            <select className="custom-select custom-select-sm" onChange={this.props.handlerChosen} id="protocol_list">
                <option value="any">любой</option>
                <option value="tcp">tcp</option>
                <option value="udp">udp</option>
            </select>
        );
    }
}

CreateProtocolList.propTypes = {
    handlerChosen: PropTypes.func.isRequired,
};

export default class CreateBodySearchTask extends React.Component {
    constructor(props){
        super(props);

        this.state = {
            disabledRadioChosenTask: true,
            disabledRadioUploadedFile: true,
            disabledRadioUploadedAllFile: true,
            searchParameters: {
                cptp: false, //ConsiderParameterTaskProcessed — учитывать параметр TaskProcessed
                tp: false, //TaskProcessed — была ли задача отмечена клиентом API как завершенная
                id: 0, //ID - уникальный цифровой идентификатор источника
                sft: "", //StatusFilteringTask - статус задачи по фильтрации
                sfdt: "", //StatusFileDownloadTask - статус задачи по скачиванию файлов
                cpfid: false, //ConsiderParameterFilesDownloaded — учитывать параметр  FilesIsDownloaded
                fid: false, //FilesIsDownloaded — выполнялась ли выгрузка файлов
                cpafid: false, //ConsiderParameterAllFilesIsDownloaded -  учитывать параметр AllFilesIsDownloaded
                afid: false, //AllFilesIsDownloaded — все ли файлы были выгружены
                iaf: { //InformationAboutFiltering — поиск информации по результатам фильтрации
                    fif: false, //FilesIsFound — были ли найдены в результате фильтрации какие либо файлы
                    cafmin: 0, //CountAllFilesMin — минимальное общее количество всех найденных в результате фильтрации файлов
                    cafmax: 0, //CountAllFilesMax — максимальное общее количество всех найденных в результате фильтрации файлов
                    safmin: 0, //SizeAllFilesMin — минимальный общий размер всех найденных  в результате фильтрации файлов
                    safmax: 0, //SizeAllFilesMax — минимальный общий размер всех найденных  в результате фильтрации файлов
                },
                ifo: { //InstalledFilteringOption — искомые опции фильтрации
                    dt: { //DateTime -  дата и время фильтруемых файлов
                        s: 0, //Start - начальное дата и время фильтруемых файлов
                        e: 0, //End - конечное дата и время фильтруемых файлов
                    },
                    p: "any", //Protocol — транспортный протокол
                    nf: { //NetworkFilters — сетевые фильтры
                        ip: { //IP — фильтры для поиска по ip адресам
                            any: [], //Any — вы обе стороны
                            src: [], //Src — только как источник
                            dst: [], //Dst — только как получатель
                        },
                        pt: { //Port — фильтры для поиска по сетевым портам
                            any: [], //Any — вы обе стороны
                            src: [], //Src — только как источник
                            dst: [], //Dst — только как получатель
                        },
                        nw: { //Network — фильтры для поиска по подсетям
                            any: [], //Any — вы обе стороны
                            src: [], //Src — только как источник
                            dst: [], //Dst — только как получатель				
                        }
                    },
                },
            },
        };

        this.getListSource = this.getListSource.bind(this);
        
        this.handlerCheckbox = this.handlerCheckbox.bind(this);
        this.handlerRadioChosen = this.handlerRadioChosen.bind(this);
        this.handlerChosenSource = this.handlerChosenSource.bind(this);
        this.handlerChosenProtocolList = this.handlerChosenProtocolList.bind(this);
        this.handlerChosenStatusDownload = this.handlerChosenStatusDownload.bind(this);
        this.handlerChosenStatusFiltering = this.handlerChosenStatusFiltering.bind(this);
    }

    handlerChosenSource(e){
        console.log("func 'handlerChosenSource', START...");
        console.log(`был выбран источник с ID '${+(e.target.value)}'`);
    }

    handlerChosenStatusFiltering(e){
        console.log("func 'handlerChosenStatusFiltering', START...");
        console.log(`был выбран статус фильтрации '${e.target.value}'`);
    }

    handlerChosenStatusDownload(e){
        console.log("func 'handlerChosenStatusDownload', START...");
        console.log(`был выбран статус скачивания '${e.target.value}'`);
    }

    handlerChosenProtocolList(e){
        console.log("func 'handlerChosenProtocolList', START...");
        console.log(`был выбран сетевой протокол '${e.target.value}'`);
    }

    handlerCheckbox(e){
        console.log("func 'handlerCheckbox', START...");
        console.log(` checked = ${e.target.checked}`);
        console.log(`name = '${e.target.name}'`);

        let objCopy = Object.assign({}, this.state);

        switch (e.target.name) {
        case "task_checkbox":
            if(e.target.checked){
                objCopy.searchParameters.cptp = false;
                this.setState({ disabledRadioChosenTask: false });
            } else {
                objCopy.searchParameters.cptp = true;
                this.setState({ disabledRadioChosenTask: true });
            }       
            break;

        case "file_uploaded_check":
            if(e.target.checked){
                objCopy.searchParameters.cpfid = false;
                this.setState({ disabledRadioUploadedFile: false });
            } else {
                objCopy.searchParameters.cpfid = true;
                this.setState({ disabledRadioUploadedFile: true });
            }       
            break;

        case "all_file_uploaded_check":
            if(e.target.checked){
                objCopy.searchParameters.cpafid = false;
                this.setState({ disabledRadioUploadedAllFile: false });
            } else {
                objCopy.searchParameters.cpafid = true;
                this.setState({ disabledRadioUploadedAllFile: true });
            } 
            break;
        }
    }

    handlerRadioChosen(e){
        console.log("func 'handlerRadioChosen', START...");
        console.log(`radio chosen '${e.target.value}'`);

        let objCopy = Object.assign({}, this.state);

        switch (e.target.name) {
        case "chose_task_complete":
            if(e.target.checked){
                objCopy.searchParameters.tp = false;
                this.setState({ disabledRadioChosenTask: false });
            } else {
                objCopy.searchParameters.tp = true;
                this.setState({ disabledRadioChosenTask: true });
            }       
            break;
    
        case "chose_uploaded_file":
            if(e.target.checked){
                objCopy.searchParameters.fid = false;
                this.setState({ disabledRadioUploadedFile: false });
            } else {
                objCopy.searchParameters.fid = true;
                this.setState({ disabledRadioUploadedFile: true });
            }       
            break;
    
        case "chose_uploaded_all_file":
            if(e.target.checked){
                objCopy.searchParameters.afid = false;
                this.setState({ disabledRadioUploadedAllFile: false });
            } else {
                objCopy.searchParameters.afid = true;
                this.setState({ disabledRadioUploadedAllFile: true });
            } 
            break;
        }
    }

    getListSource(){

        console.log("func 'getListSource', create source list...");

        return Object.keys(this.props.listSources).sort((a, b) => a < b).map((sourceID) => {
            let isDisabled = !(this.props.listSources[sourceID].connectStatus);          

            return (
                <option 
                    key={`key_sour_${this.props.listSources[sourceID].id}`} 
                    value={sourceID} 
                    disabled={isDisabled} >
                    {`${sourceID} ${this.props.listSources[sourceID].shortName}`}
                </option>
            );
        });
    }

    render(){
        return (
            <React.Fragment>
                <Card className="mb-2" body>
                    <Form.Row>
                        <Form.Group as={Col}>
                            <Form.Control onChange={this.handlerChosenSource} as="select" size="sm">
                                <option value={0}>источник</option>
                                {this.getListSource()}
                            </Form.Control>
                        </Form.Group>
                        <Form.Group as={Col}>
                            <Form.Control onChange={this.handlerChosenStatusFiltering} as="select" size="sm">
                                <option value="">статус фильтрации</option>
                                <option value="wait">готовится к выполнению</option>
                                <option value="refused">oтклонена</option>
                                <option value="execute">выполняется</option>
                                <option value="complete">завершена успешно</option>
                                <option value="stop">остановлена пользователем</option>
                            </Form.Control>
                        </Form.Group>
                        <Form.Group as={Col}>
                            <Form.Control onChange={this.handlerChosenStatusDownload} as="select" size="sm">
                                <option value="">статус выгрузки файлов</option>
                                <option value="wait">готовится к выполнению</option>
                                <option value="refused">oтклонена</option>
                                <option value="execute">выполняется</option>
                                <option value="not executed">не выполнялась</option>
                                <option value="complete">завершена успешно</option>
                                <option value="stop">остановлена пользователем</option>
                            </Form.Control>
                        </Form.Group>
                        <Form.Group as={Col} className="mt-1 ml-3">
                            <Form inline>
                                <Form.Check type="checkbox" onClick={this.handlerCheckbox} name="task_checkbox"/>
                                <small className="ml-1">задача</small>
                                <Form.Check 
                                    custom 
                                    type="radio"
                                    onClick={this.handlerRadioChosen} 
                                    id="r_task_complete" 
                                    value={true} 
                                    label="" 
                                    className="mt-1 ml-3" 
                                    name="chose_task_complete" 
                                    disabled={this.state.disabledRadioChosenTask}
                                    defaultChecked />
                                <small className="ml-1">закрыта</small>
                                <Form.Check 
                                    custom 
                                    type="radio"
                                    onClick={this.handlerRadioChosen}  
                                    id="r_task_not_complete" 
                                    value={false} 
                                    label="" 
                                    className="mt-1 ml-3" 
                                    name="chose_task_complete"
                                    disabled={this.state.disabledRadioChosenTask} />
                                <small className="ml-1">открыта</small>
                            </Form>
                        </Form.Group>
                    </Form.Row>
                    <Form.Row>
                        <Form.Group as={Col} className="text-left">
                            <Form.Row className="ml-1">
                                <Form.Check type="checkbox" className="mt-n2"/>
                                <small className="ml-1 mt-n2">файлы найдены</small>
                            </Form.Row>
                            <Form.Row className="ml-1">
                                <Form.Check type="checkbox" onClick={this.handlerCheckbox} name="file_uploaded_check"/>
                                <small className="ml-1">выгрузка выполнялась</small>
                                <Form.Check 
                                    custom 
                                    type="radio"
                                    onClick={this.handlerRadioChosen} 
                                    id="r_upload_file" 
                                    value={true} 
                                    label="" 
                                    className="mt-1 ml-3" 
                                    name="chose_uploaded_file" 
                                    disabled={this.state.disabledRadioUploadedFile}
                                    defaultChecked />
                                <small className="ml-1">да</small>
                                <Form.Check 
                                    custom 
                                    type="radio"
                                    onClick={this.handlerRadioChosen} 
                                    id="r_not_upload_file" 
                                    value={false} 
                                    label="" 
                                    className="mt-1 ml-3" 
                                    name="chose_uploaded_file"
                                    disabled={this.state.disabledRadioUploadedFile} />
                                <small className="ml-1">нет</small>
                            </Form.Row>
                            <Form.Row className="ml-1">
                                <Form.Check type="checkbox" onClick={this.handlerCheckbox} name="all_file_uploaded_check"/>
                                <small className="ml-1">все файлы выгружены</small>
                                <Form.Check 
                                    custom 
                                    type="radio"
                                    onClick={this.handlerRadioChosen} 
                                    id="r_upload_all_file" 
                                    value={true} 
                                    label="" 
                                    className="mt-1 ml-3" 
                                    name="chose_uploaded_all_file" 
                                    disabled={this.state.disabledRadioUploadedAllFile}
                                    defaultChecked />
                                <small className="ml-1">да</small>
                                <Form.Check 
                                    custom 
                                    type="radio"
                                    onClick={this.handlerRadioChosen} 
                                    id="r_not_upload_all_file" 
                                    value={false} 
                                    label="" 
                                    className="mt-1 ml-3" 
                                    name="chose_uploaded_all_file"
                                    disabled={this.state.disabledRadioUploadedAllFile} />
                                <small className="ml-1">нет</small>
                            </Form.Row>
                        </Form.Group>
                        <Form.Group as={Col} className="text-left">
                            <small>найдено файлов</small>
                            <Form.Row>
                                <Form.Group as={Col}>
                                    <Form.Control type="input" size="sm" placeholder="min" />
                                </Form.Group>
                                <Form.Group as={Col}>
                                    <Form.Control type="input" size="sm" placeholder="max" />
                                </Form.Group>
                            </Form.Row>
                        </Form.Group>
                        <Form.Group as={Col} className="text-left">
                            <small>общий размер найденных файлов</small>
                            <Form.Row>
                                <Form.Group as={Col}>
                                    <Form.Control type="input" size="sm" placeholder="min" />
                                </Form.Group>
                                <Form.Group as={Col}>
                                    <Form.Control type="input" size="sm" placeholder="max" />
                                </Form.Group>
                            </Form.Row>
                        </Form.Group>    
                    </Form.Row>                    
                    <Form.Row className="mt-n3">
                        <Col md={5}>
                            <Row>
                                <Col md={6}>
                                    <small className="mr-1">начальное время</small>
                                    <Form.Row>
                                        <DatePicker 
                                            className="form-control form-control-sm green-border"
                                            //selected={this.props.startDate}
                                            //onChange={this.props.handleChangeStartDate}
                                            maxDate={new Date()}
                                            showTimeInput
                                            selectsStart
                                            isClearable
                                            timeFormat="p"
                                            timeInputLabel="Time:"
                                            dateFormat="dd.MM.yyyy hh:mm aa" />
                                    </Form.Row>
                                </Col>
                                <Col md={6}>
                                    <small className="mr-1">конечное время</small>
                                    <Form.Row>
                                        <DatePicker 
                                            className="form-control form-control-sm red-border"
                                            //selected={this.props.endDate}
                                            //onChange={this.props.handleChangeEndDate}
                                            maxDate={new Date()}
                                            showTimeInput
                                            selectsEnd
                                            isClearable
                                            timeFormat="p"
                                            timeInputLabel="Time:"
                                            dateFormat="dd.MM.yyyy hh:mm aa" />
                                    </Form.Row>
                                </Col>
                            </Row>
                        </Col>
                        <Col md={2} className="text-right">
                            <small className="mr-1">сет. протокол</small>
                            <CreateProtocolList handlerChosen={this.handlerChosenProtocolList} />
                        </Col>
                        <Col md={5}>
                            <Form.Row>
                                <TokenInput 
                                    className="react-token-input"
                                    placeholder="ip адрес, порт или подсеть" />
                                <a href="#">
                                    <img className="clickable_icon" src="../images/icons8-help-28.png" alt=""></img>
                                </a>
                            </Form.Row>
                        </Col>
                    </Form.Row>
                    <Row>
                        <Col className="text-right mt-4 mb-n2">
                            <Button size="sm" onClick={this.addPortNetworkIP} variant="outline-primary">
                                поиск
                            </Button>
                        </Col>
                    </Row>
                </Card>
            </React.Fragment>
        );
    }
}

CreateBodySearchTask.propTypes = {
    socketIo: PropTypes.object.isRequired,
    listSources: PropTypes.object.isRequired,
};