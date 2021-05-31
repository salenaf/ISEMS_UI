import React from "react";
import { Badge, Button, Col, Row, Form, FormControl, InputGroup } from "react-bootstrap";
import Typography from "@material-ui/core/Typography";
import PropTypes from "prop-types";

import CreateChipSource from "../../commons/createChipSource.jsx";
import CreateSourceList from "../../commons/createSourceList.jsx";
import CreateRangeSlider from "./createRangeSlider.jsx";
import CreateListInputValue from "./createListInputValue.jsx";
import CreateChangeTemplateType from "./createChangeTemplateType.jsx";
import CreateFormControlChangeTime from "./createFormControlChangeTime.jsx";
import CreateListNetworkParameters from "./createListNetworkParameters.jsx";
import CreateInformationTimeFiltrationInterval from "./createInformationTimeFiltrationInterval.jsx";

export default function CreateForm(props){ 
    let daysOfWeek = [];
    let textColor = "text-primary";

    let showParametersFiltration = () => {
        if(props.templateParameters.templateType !== "filtration"){
            return;
        }

        return (
            <React.Fragment>
                <Row>
                    <Col md={12} className="text-left mt-2">
                        <Typography variant="subtitle1" color="textSecondary">
                        Опции для фильтрации файлов сетевого трафика.
                        </Typography>
                    </Col>
                </Row>
                <CreateInformationTimeFiltrationInterval
                    minHour={props.parametersFiltration.dateTime.minHour}
                    maxHour={props.parametersFiltration.dateTime.maxHour}
                    timeTrigger={props.templateParameters.templateTime.timeTrigger} />                
                <Row>
                    <Col md={4} className="text-right">
                        <Typography variant="subtitle1" color="textSecondary">
                        сетевой протокол:
                        </Typography>
                    </Col>
                    <Col md={8} className="text-left">
                        {(props.parametersFiltration.networkProtocol) ? "любой" : props.parametersFiltration.networkProtocol}
                    </Col>
                </Row>                
                <Row>
                    <Col md={4} className="text-right">
                        <Typography variant="subtitle1" color="textSecondary">
                        ip адреса:
                        </Typography>
                    </Col>
                    <Col md={8} className="text-left">
                        <CreateListNetworkParameters 
                            type="ip"
                            inputValue={props.parametersFiltration.inputs.inputValue} />
                    </Col>
                </Row>                
                <Row>
                    <Col md={4} className="text-right">
                        <Typography variant="subtitle1" color="textSecondary">
                        сети:
                        </Typography>
                    </Col>
                    <Col md={8} className="text-left">
                        <CreateListNetworkParameters 
                            type="nw"
                            inputValue={props.parametersFiltration.inputs.inputValue} />
                    </Col>
                </Row>       
                <Row>
                    <Col md={4} className="text-right">
                        <Typography variant="subtitle1" color="textSecondary">
                        сетевые порты:
                        </Typography>
                    </Col>
                    <Col md={8} className="text-left">
                        <CreateListNetworkParameters 
                            type="pt"
                            inputValue={props.parametersFiltration.inputs.inputValue} />
                    </Col>
                </Row>
            </React.Fragment>
        );
    };

    switch(props.numberSteppers){
    case 0:
        return (
            <Row>
                <Col md={12} className="text-center">
                    <CreateChangeTemplateType 
                        templateType={props.templateParameters.templateType}
                        handlerChangeTemplateType={props.handlerChangeTemplateType} />
                </Col>
            </Row>
        );

    case 1:
        return <CreateFormControlChangeTime
            timeTrigger={props.templateParameters.templateTime.timeTrigger}
            listSelectedDays={props.templateParameters.templateTime.listSelectedDays}
            checkSelectedType={props.templateParameters.templateTime.checkSelectedType}
            handlerChangeTimeTrigger={props.handlerChangeTimeTrigger}
            handlerChangeCheckboxDayOfWeek={props.handlerChangeCheckboxDayOfWeek}
            handlerChangeTemplateTimeRadioType={props.handlerChangeTemplateTimeRadioType} />;

    case 2:
        return (
            <React.Fragment>
                <Row className="pt-3">
                    <Col md={5} className="text-left">
                        <CreateSourceList 
                            typeModal={"новая"}
                            hiddenFields={false}
                            listSources={props.listSources}
                            currentSource={props.templateParameters.templeteChosedSource}
                            handlerChosen={props.handlerChosenSource}
                            swithCheckConnectionStatus={false} />        
                    </Col>
                    <Col md={7} className="mt-n1 text-left">
                        <CreateChipSource 
                            chipData={props.templateParameters.templateListSource} 
                            handleDelete={props.handlerDeleteSource}/>
                    </Col>
                </Row>
                <Row>
                    <Col md={12} className="text-left mt-n2">
                        <Typography variant="body2" color="textSecondary">
                            {"* если в поле \"выберите источник\" не выбран ни один из источников, то тогда считается что шаблон распространяется на все источники"}
                        </Typography>
                    </Col>
                </Row>
            </React.Fragment>
        );                           

    case 3:
        return (
            <React.Fragment>
                <Row>
                    <Col sm="12" className="text-left">
                        <CreateInformationTimeFiltrationInterval
                            minHour={props.parametersFiltration.dateTime.minHour}
                            maxHour={props.parametersFiltration.dateTime.maxHour}
                            timeTrigger={props.templateParameters.templateTime.timeTrigger} />                
                        <CreateRangeSlider 
                            minHour={props.parametersFiltration.dateTime.minHour}
                            maxHour={props.parametersFiltration.dateTime.maxHour}
                            handlerChangeRangeSlider={props.handlerChangeRangeSlider} />
                    </Col>
                </Row>
                <Row className="mt-2">
                    <Col className="text-right" sm="2">
                        <small className="text-muted">сетевой протокол</small>
                        <CreateProtocolList 
                            defaultNetworkProtocol={props.parametersFiltration.networkProtocol} 
                            handlerChosen={props.handlerChosenNetworkProtocol} />
                    </Col>
                    <Col className="text-right mt-4" sm="3">
                        <Form inline className="text-right">
                            <Form.Check onClick={props.handlerCheckRadioInput} custom type="radio" id="r_direction_any" value="any" label="any" className="mt-1 ml-3" name="choseNwType" defaultChecked />
                            <Form.Check onClick={props.handlerCheckRadioInput} custom type="radio" id="r_direction_src" value="src" label="src" className="mt-1 ml-3" name="choseNwType" />
                            <Form.Check onClick={props.handlerCheckRadioInput} custom type="radio" id="r_direction_dst" value="dst" label="dst" className="mt-1 ml-3" name="choseNwType" />
                        </Form>
                    </Col>
                    <Col className="text-right" sm="7"> 
                        <small className="text-muted">ip адрес, сеть или сетевой порт</small>
                        <InputGroup size="sm">                           
                            <FormControl
                                id="input_ip_network_port"
                                aria-describedby="basic-addon2"
                                onChange={props.handlerInput}
                                onKeyPress={props.handleKeyPress}
                                isValid={props.parametersFiltration.inputs.inputFieldIsValid}
                                isInvalid={props.parametersFiltration.inputs.inputFieldIsInvalid} 
                                placeholder="введите ip адрес, подсеть или сетевой порт" />
                            <InputGroup.Append>
                                <Button onClick={props.handlerAddPortNetworkIP} variant="outline-secondary">
                                    добавить
                                </Button>
                            </InputGroup.Append>
                        </InputGroup>
                    </Col>
                </Row>
                <CreateListInputValue 
                    inputValue={props.parametersFiltration.inputs.inputValue}
                    hendlerDeleteAddedElem={props.hendlerDeleteAddedElem} />
            </React.Fragment>
        );

    case 4: 
        for(let day in props.templateParameters.templateTime.listSelectedDays){
            if(props.templateParameters.templateTime.listSelectedDays[day].checked){
                daysOfWeek.push(props.templateParameters.templateTime.listSelectedDays[day].name);
            }
        }

        return (
            <React.Fragment>
                <Row>
                    <Col md={4} className="text-right">
                        <Typography variant="subtitle1" color="textSecondary">тип шаблона:</Typography>
                    </Col>
                    <Col md={8} className="text-left">{(props.templateParameters.templateType === "telemetry") ? "телеметрия": "фильтрация"}</Col>
                </Row>
                <Row>
                    <Col md={4} className="text-right">
                        <Typography variant="subtitle1" color="textSecondary">дни недели:</Typography>
                    </Col>
                    <Col md={8} className="text-left">{(()=>{
                        let i = 0;
                        let num = daysOfWeek.length;
                        let comma = ", ";
                        
                        return daysOfWeek.map((item) => {
                            if(item === "суббота" || item === "воскресенье"){
                                textColor = "text-danger";
                            } else {
                                textColor = "text-primary";
                            }

                            return (num > ++i) ? <span key={`key_day_of_week_${item}`} className={textColor}>{item+comma}</span> : <span key={`key_day_of_week_${item}`} className={textColor}>{item}</span>;
                        });
                    })()}</Col>
                </Row>
                <Row>
                    <Col md={4} className="text-right">
                        <Typography variant="subtitle1" color="textSecondary">время выполнения:</Typography>                        
                    </Col>
                    <Col md={8} className="text-left">
                        {(() => {
                            let hour = props.templateParameters.templateTime.timeTrigger.getHours();
                            let minute = props.templateParameters.templateTime.timeTrigger.getMinutes();

                            return ((hour < 10) ? "0"+hour : hour)+":"+((minute < 10) ? "0"+minute : minute);
                        })()}
                    </Col>
                </Row>
                <Row>
                    <Col md={4} className="text-right">
                        <Typography variant="subtitle1" color="textSecondary">список источников для выполнения:</Typography>                        
                    </Col>
                    <Col md={8} className="text-left">
                        {(() => {
                            if(props.templateParameters.templateListSource.length === 0){
                                return "на всех источниках";
                            }

                            return props.templateParameters.templateListSource.map((item) => {
                                return <Badge pill variant="secondary" className="mr-1" key={`key_sid_${item}`}>{item}</Badge>;
                            });
                        })()}
                    </Col>
                </Row>
                {showParametersFiltration()}
            </React.Fragment>
        );

    default:
        return <Row><Col md={12}>Ошибка!!!</Col></Row>;
    }
}

CreateForm.propTypes = {
    listSources: PropTypes.object.isRequired,
    numberSteppers: PropTypes.number.isRequired,
    templateParameters: PropTypes.object.isRequired,
    parametersFiltration: PropTypes.object.isRequired,
    handlerInput: PropTypes.func.isRequired,
    handleKeyPress: PropTypes.func.isRequired,
    handlerAddPortNetworkIP: PropTypes.func.isRequired,
    handlerCheckRadioInput: PropTypes.func.isRequired,
    hendlerDeleteAddedElem: PropTypes.func.isRequired,
    handlerChosenSource: PropTypes.func.isRequired,
    handlerDeleteSource: PropTypes.func.isRequired,
    handlerChangeRangeSlider: PropTypes.func.isRequired,
    handlerChangeTimeTrigger: PropTypes.func.isRequired,
    handlerChangeTemplateType: PropTypes.func.isRequired,
    handlerChosenNetworkProtocol: PropTypes.func.isRequired,
    handlerChangeCheckboxDayOfWeek: PropTypes.func.isRequired,
    handlerChangeTemplateTimeRadioType: PropTypes.func.isRequired,
};

function CreateProtocolList(props){
    const np = [
        {t:"any", n:"любой"},
        {t:"tcp", n:"tcp"},
        {t:"udp", n:"udp"},
    ];

    return (
        <select 
            defaultValue={props.defaultNetworkProtocol}
            className="custom-select custom-select-sm" 
            onChange={props.handlerChosen} 
            id="protocol_list">
            {np.map((item) => {
                return <option key={`key_p_${item.t}`} value={item.t}>{item.n}</option>;
            })}
        </select>
    );
}

CreateProtocolList.propTypes = {
    handlerChosen: PropTypes.func.isRequired,
    defaultNetworkProtocol: PropTypes.string.isRequired,
};
