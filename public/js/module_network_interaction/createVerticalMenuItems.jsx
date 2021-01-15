import React from "react";
import ReactDOM from "react-dom";
import { Tab, Tabs } from "@material-ui/core";

class CreateMenuItemsVertical extends React.Component {
    constructor(props){
        super(props);

        this.menuItem = {
            "/network_interaction": { "num": 0, "label": "прогресс" },
            "/network_interaction_page_file_download": { "num": 1, "label": "выгрузка файлов" },
            "/network_interaction_page_search_tasks": { "num": 2, "label": "поиск" },
            "/network_interaction_page_statistics_and_analytics": { "num": 3, "label": "аналитика" },
            "/network_interaction_page_source_telemetry": { "num": 4, "label": "телеметрия" },
            "/network_interaction_page_notification_log": { "num": 5, "label": "журнал событий" },
            "/network_interaction_page_template_log": { "num": 6, "label": "журнал шаблонов" },
        };
    }

    getSelectedMenuItem(){
        if((typeof this.menuItem[window.location.pathname] === "undefined") || (this.menuItem[window.location.pathname] === null)){           
            return 3;
        }
    
        return (typeof this.menuItem[window.location.pathname].num !== "undefined") ? this.menuItem[window.location.pathname].num : 0;
    }

    createMenu(){
        let list = [];
        for(let item in this.menuItem){
            if(item === "/network_interaction_page_template_log"){
                list.push(<Tab href={item} disabled label={this.menuItem[item].label} key={`menu_item_${this.menuItem[item].num}`} />);
            } else {
                list.push(<Tab href={item} label={this.menuItem[item].label} key={`menu_item_${this.menuItem[item].num}`} />);
            }
        }

        return (
            <Tabs
                value={this.getSelectedMenuItem.call(this)}
                indicatorColor="primary"
                orientation="vertical"
                variant="scrollable"
                aria-label="Vertical tabs example" >
                {list}
            </Tabs>
        );
    }

    render(){
        return this.createMenu.call(this);
    }
}

ReactDOM.render(<CreateMenuItemsVertical />, document.getElementById("header-page-vertical_menu"));