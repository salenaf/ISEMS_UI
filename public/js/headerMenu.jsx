'use strict'

import React from 'react'
import ReactDOM from 'react-dom'

class CreateHeaderMenu extends React.Component {
  constructor(props) {
    super(props)
  }

  render() {
    let createMenu = function (objMenuItem) {
      let tmpArr = []
      for (let key in objMenuItem) {
        let submenuIsExist = Object.keys(objMenuItem[key].submenu).length
        if (submenuIsExist === 0) {
          tmpArr.push(
            <li key={key}>
              <a href={key}>{objMenuItem[key].name}</a>
            </li>
          )
          continue
        }

        let newString = (
          <li key={key}>
            <a
              href='#'
              className='dropdown-toggle'
              id='ddlmenuItem'
              data-toggle='dropdown'
            >
              {objMenuItem[key].name} <i className='fa fa-angle-down' />
            </a>
            <ul
              className='dropdown-menu'
              role='menu'
              aria-labelledby='ddlmenuItem'
            >
              {createMenu(objMenuItem[key].submenu)}
            </ul>
          </li>
        )

        tmpArr.push(newString)
      }

      return tmpArr
    }

    let menuSettings = this.props.header.menuSettings
    let newMenu = createMenu(menuSettings)

    newMenu.unshift(
      <li key='index'>
        <a href='/' className='menu-top-active'>
          ГЛАВНАЯ
            </a>
      </li>
    )

    return newMenu
  }
}

ReactDOM.render(
  <CreateHeaderMenu header={resivedFromServer} />,
  document.getElementById('menu-top')
)
