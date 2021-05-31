import React from "react";
import propTypes from "prop-types";

import { Button, Badge, Container, Col,  Row, Form, Tab, ListGroup, Sonnet} from "react-bootstrap";

// import ReactDOM from "reactDom";
import { DragDropContext, Droppable, Draggable } from "react-beautiful-dnd";

import { CreateListEntity } from "./../organizations_and_sources/createBodyManagementEntity.jsx";
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
            selected: getItems(5, 10),
            filter_search: "",
            // visSpisok: "invisible",
        };

        this.listShortEntity = {
            shortListDivision: [
                {source_list: Array(0), id: "04c83b09321869a9887d804d0ca51", id_organization: "4cc9c5679bb843631592d154d565", name: "Главное управление заводом"},
                {source_list: Array(1), id: "2b5add69cb563572ca088670a58", id_organization: "4cc9c5679bb843631592d154d565", name: "Цех №1"},
            ],
            shortListOrganization: [
                {division_or_branch_list_id: Array(4), id: "4cc9c5679bb843631592d154d565", name: "АвтоЗавод", field_activity: "коммерческая деятельность"},
                {division_or_branch_list_id: Array(1), id: "68c2066525a2933c2ca192197426", name: "Первая тестовая организация IT (им. Спайдермена)", field_activity: "наука и образование"},
            ],
            shortListSource: [
                {
                    connect_status: true,
                    connect_time: 1611731250,
                    date_register: 1603981817847,
                    id: "b46720c197285d36935c9c5c289a5",
                    id_division: "32681abb89ddc1b838954a7282b64",
                    information_about_app: {version: "v1.5.3", date: "26.01.2021"},
                    short_name: "Test Source 1",
                    source_id: 1000,
                },
                {
                    connect_status: false,
                    connect_time: 0,
                    date_register: 1609239867997,
                    id: "a40762730400a7c1d837d7b9a749",
                    id_division: "2b5add69cb563572ca088670a58",
                    information_about_app: {version: "не определена", date: "не определено"},
                    short_name: "Test 13333",
                    source_id: 13333,
                },
            ],
        };
        
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

        this.listOrganization =this.listOrganization.bind(this);

        this.listDivision= this.listOrganization.bind(this);


        this.onChangeSearch  = this.onChangeSearch.bind(this);
        this.showSpisok     = this.showSpisok.bind(this);
        this.showContainer  = this.showContainer.bind(this);
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
    
    showContainer(){
        let vis = "invisible";
        vis = "invisible";
        let container =   <div className={vis}>
            <Container>
                <Row className="justify-content-md-center"> 
                    <Col className="text-left" md="auto">
                        {/* <CreateListEntity 
                            listShortEntity={this.listShortEntity}
                            handlerSelected={this.handlerSelected} />   */}
                    </Col>
                    <Col md="auto">
              
                    </Col>
                </Row>
   
            </Container>
            <DragDropContext onDragEnd={this.onDragEnd}>
                <Container>
                    <Row className="justify-content-md-center"> {/*className="alert alert-primary" */}
                        <Col md="auto" >
                           
                            <div>
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
                                </Droppable>;
                            </div>
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
        </div>;


        return container;

    }
    // eslint-disable-next-line no-dupe-class-members
    listOrganization(){
        let listTmp = {};
        this.props.listShortEntity.shortListOrganization.forEach((item) => {
            listTmp[item.name] = item.id;
        });

        let arrayTmp = Object.keys(listTmp).sort().map((name) => {
            return <option className="form-control mr-sm-2" key={`key_org_${listTmp[name]}`} value={`organization:${listTmp[name]}`}>{name}</option>;
        });

        return arrayTmp;
    }

    // eslint-disable-next-line no-dupe-class-members
    listDivision(){       
        let listTmp = {};
        this.props.listShortEntity.shortListDivision.forEach((item) => {
            listTmp[item.name] = {
                did: item.id,
                oid: item.id_organization,
            };
        });

        let arrayTmp = Object.keys(listTmp).sort().map((name) => {
            return <option className="form-control mr-sm-2" key={`key_divi_${listTmp[name].did}`} value={`division:${listTmp[name].did}`}>{name}</option>;
        });

        return arrayTmp;
    }
    
    showSpisok(){
        let vis ="invisible" ;
        //  let vis = this.state.visSpisok;
        let spisok = <div></div>;
        if(this.state.filter_search!=""){
            vis = "visible";
            let str = "dropdown_all_entity";
            console.log("vis");
            console.log(vis);
            spisok =  <div className={vis}>
                <form>
                    <select multiple className = "form-control"   id = {str}>
                        <option></option>
                        <optgroup label="организации">
                            {this.listOrganization()}
                        </optgroup>
                        <optgroup label="подразделения или филиалы">
                            {this.listDivision()}
                        </optgroup>
                        {/*  <optgroup label="источники">
                           {this.listSource()} 
                        </optgroup>*/}
                    </select>
                </form>     
            </div>;
        } else {

            spisok = <div></div>  ;
        }

        return spisok;
    }
    

    onChangeSearch(e) {
        let value = e.target.value;


        this.setState({
            filter_search:  value,
            //visSpisok:      "visible",
        });
    }

    render() {
        
        // let items = new Map(this.state.items);
        // let selected =new Map(this.state.selected);
        return (  
            <div>
                Сотрировка элементов
                <br/>
                <br/>
                <Col md={6}>
                    <input className="form-control mr-sm-2" placeholder="Введите" value = {this.state.filter_search} onChange = {this.onChangeSearch}  type="search" aria-label="Search"/>
                        
                </Col>
               
                {this.showSpisok()}
                {this.showContainer()}
            </div>
        );
    }
}


CreateBody.propTypes ={
    socketIo: propTypes.object.isRequired,
    listShortEntity: propTypes.object.isRequired,
};