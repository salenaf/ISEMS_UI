import React from "react";
import propTypes from "prop-types";

import { Button, Badge, Container, Col,  Row, Form } from "react-bootstrap";

// import ReactDOM from "reactDom";
import { DragDropContext, Droppable, Draggable } from "react-beautiful-dnd";

import CreateListEntity from "./../organizations_and_sources/createBodyManagementEntity.jsx";
//import subjectsArray from "./schedule-data";

/* 
 * Test
 * 
 */

const getItems = (count, offset = 0) =>
    Array.from({ length: count }, (v, k) => k).map((k) => ({
        id: `item-${k + offset}`,
        content: `Тута находится что-то очень длинное и невероятно интересное ${k + offset}`
    }));
// a little function to help us with reordering the result
const reorder = (list, startIndex, endIndex) => {
    const result = Array.from(list);
    const [removed] = result.splice(startIndex, 1);
    result.splice(endIndex, 0, removed);

    return result;
};

/**
 * Moves an item from one list to another list.
 */
const move = (source, destination, droppableSource, droppableDestination) => {
    // console.log(source);
    const sourceClone = Array.from(source);
    const destClone = Array.from(destination);
    const [removed] = sourceClone.splice(droppableSource.index, 1);

    destClone.splice(droppableDestination.index, 0, removed);

    const result = {};
    result[droppableSource.droppableId] = sourceClone;
    result[droppableDestination.droppableId] = destClone;
    console.log("Итог");
    console.log(result);
    return result;
};

const grid = 5;

const getItemStyle = (isDragging, draggableStyle) => ({
    // несколько основных стилей, чтобы предметы выглядели немного лучше
    userSelect: "none",
    borderRadius: "5px",
    border: isDragging ? "2px solid palevioletred" : "2px solid lightblue", 
    // fontSize: 18, размер шрифта 
    outline: "black",
    padding: grid * 2,
    margin: `0 0 ${grid}px 0`,

    // изменить цвет фона при перетаскиванииisDragging ? 
    background: "white",
    // border: isDragging ? "lightgrey" :"white" ,
    // стили, которые нам нужно применить к перетаскиваемым объектам
    ...draggableStyle
});

const getListStyle = (isDraggingOver) => ({
    // задний фон lightblue
    background: isDraggingOver ? "white" : "white",
    padding: grid,
    //border: "black",
    borderRadius: "5px",
    width: 500
});


export default class CreateBody extends React.Component{
    constructor(props){
        super(props);
        this.state = {
            items: getItems(6),
            selected: getItems(5, 10)
        };
        this.listShortEntity = [
            "123",
            "qwe",
            "asd",
            "zxc",
        ];
        /**
         * A semi-generic way to handle multiple lists. Matches
         * the IDs of the droppable container to the names of the
         * source arrays stored in the state.
         */
        this.handlerSelected = this.handlerSelected.bind(this);
        this.id2List = {
            droppable: "items",
            droppable2: "selected"
        };
    
        this.getList = (id) => this.state[this.id2List[id]];
    
        this.onDragEnd = (result) => {
            const { source, destination } = result;
    
            // dropped outside the list
            if (!destination) {
                return;
            }
    
            if (source.droppableId === destination.droppableId) {
                const items = reorder(
                    this.getList(source.droppableId),
                    source.index,
                    destination.index
                );
    
                let state = { items };
    
                if (source.droppableId === "droppable2") {
                    state = { selected: items };
                }
    
                this.setState(state);
            } else {
                const result = move(
                    this.getList(source.droppableId),
                    this.getList(destination.droppableId),
                    source,
                    destination
                );
    
                this.setState({
                    items: result.droppable,
                    selected: result.droppable2
                });
            }
        };
    }

    handlerSelected(obj){
        this.props.socketIo.emit("entity information", { 
            actionType: "get info about organization or division",
            arguments: obj
        });
    }
    listOrganization(){
        let listTmp = {};
        this.listShortEntity.forEach((item) => {
            listTmp[item.name] = item.id;
        });

        let arrayTmp = Object.keys(listTmp).sort().map((name) => {
            return <option key={`key_org_${listTmp[name]}`} value={`organization:${listTmp[name]}`}>{name}</option>;
        });

        return arrayTmp;
    }

    listDivision(){       
        let listTmp = {};
        this.listShortEntity.forEach((item) => {
            listTmp[item.name] = {
                did: item.id,
                oid: item.id_organization,
            };
        });

        let arrayTmp = Object.keys(listTmp).sort().map((name) => {
            return <option key={`key_divi_${listTmp[name].did}`} value={`division:${listTmp[name].did}`}>{name}</option>;
        });

        return arrayTmp;
    }

    // listSource(){
    //     let listTmp = {};
    //     this.listShortEntityforEach((item) => {           
    //         let organizationId = "";
    //         for(let d of this.listShortEntity){
    //             if(d.id === item.id_division){
    //                 organizationId = d.id_organization;

    //                 break;
    //             }
    //         }

    //         listTmp[item.short_name] = {
    //             id: item.source_id,
    //             sid: item.id,
    //             did: item.id_division,
    //             oid: organizationId,
    //         };
    //     });

    //     let arrayTmp = Object.keys(listTmp).sort((a, b) => a < b).map((name) => {          
    //         return <option key={`key_sour_${listTmp[name].sid}`} value={`source:${listTmp[name].sid}`}>{`${listTmp[name].id} (${name})`}</option>;
    //     });

    //     return arrayTmp;
    // }
    // Обычно вы хотите разделить все на отдельные компоненты. 
    // Но в этом примере для простоты все сделано в одном месте.
    render() {
        
        // let items = new Map(this.state.items);
        // let selected =new Map(this.state.selected);
        return (  
            <div>
                Сотрировка элементов
                <br/>
                <br/>
                <Container>
                    <Row className="justify-content-md-center"> 
                        <Col md="auto">
                            <Form.Control as="select" size="sm"  id="select_list_organization">
                                {[<option value="all" defaultValue key={"select_organization_option_none"}>добавить организацию</option>].concat(
                                    this.listShortEntity.map((item) => {
                                        return <option value={item.id} key={`select_${item.id}_option`}>{item.name}</option>;
                                    }))}
                            </Form.Control>
                        </Col>
                        <Col md="auto">
                           
                        </Col>
                    </Row>
                
                </Container>
                <DragDropContext onDragEnd={this.onDragEnd}>
                    <Container>
                        <Row className="justify-content-md-center"> {/*className="alert alert-primary" */}
                            <Col md="auto" >
                                <Droppable droppableId="droppable" >
                                    {(provided, snapshot) => (
                                        <div
                                            ref={provided.innerRef}
                                            style={getListStyle(snapshot.isDraggingOver)}>
                                            {this.state.items.map((item, index) => (
                                                <Draggable
                                                    key={item.id}
                                                    draggableId={item.id}
                                                    index={index}>
                                                    {(provided, snapshot) => (
                                                        <div
                                                            ref={provided.innerRef}
                                                            {...provided.draggableProps}
                                                            {...provided.dragHandleProps}
                                                            style={getItemStyle(
                                                                snapshot.isDragging,
                                                                provided.draggableProps.style
                                                            )}>
                                                            {item.content}
                                                        </div>
                                                    )}
                                                </Draggable>
                                            ))}
                                            {provided.placeholder}
                                        </div>
                                    )}
                                </Droppable>
                            </Col>
                            <Col md="auto">
                
                                <Droppable droppableId="droppable2" >
                                    {(provided, snapshot) => (
                                        <div
                                            ref={provided.innerRef}
                                            style={getListStyle(snapshot.isDraggingOver)}>
                                            {this.state.selected.map((item, index) => (
                                                <Draggable
                                                    key={item.id}
                                                    draggableId={item.id}
                                                    index={index}>
                                                    {(provided, snapshot) => (
                                                        <div
                                                            ref={provided.innerRef}
                                                            {...provided.draggableProps}
                                                            {...provided.dragHandleProps}
                                                            style={getItemStyle(
                                                                snapshot.isDragging,
                                                                provided.draggableProps.style
                                                            )}>
                                                            {item.content}
                                                        </div>
                                                    )}
                                                </Draggable>
                                            ))}
                                            {provided.placeholder}
                                        </div>
                                    )}
                                </Droppable>
                            </Col>
                        </Row>
                    </Container>
                </DragDropContext>
            </div>
        );
    }
}


CreateBody.propTypes ={
    ss: propTypes.func.isRequired,
    socketIo: propTypes.object.isRequired,
};