import React from 'react'
import { Nav, Navbar, NavDropdown } from 'react-bootstrap'
import ReactDOM from 'react-dom'

class CreateHeaderMenu extends React.Component {
  constructor(props) {
    super(props)
  }

  /*render() {
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
  }*/

  render() {
    let createMenu = function (objMenuItem, isDropDown) {
      let classLi = (isDropDown) ? 'nav-item dropdown' : 'nav-item'
      let classA = (isDropDown) ? 'dropdown-item' : 'nav-link'
      let tmpArr = []
      for (let key in objMenuItem) {
        let submenuIsExist = Object.keys(objMenuItem[key].submenu).length
        if (submenuIsExist === 0) {
          if (isDropDown) {
            tmpArr.push(
              <a className={classA} key={key} href={key}>{objMenuItem[key].name}</a>
            )
            continue
          } else {
            tmpArr.push(
              <li className={classLi} key={key}>
                <a className={classA} href={key}>{objMenuItem[key].name}</a>
              </li>
            )
            continue
          }
        }

        let newString = (
          <li className="nav-item dropdown" key={key}>
            <a
              href="#"
              role="button"
              className="nav-link dropdown-toggle"
              id="ddlmenuItem"
              data-toggle="dropdown"
              aria-haspopup="true"
              aria-expanded="false"
            ></a>
            <div className="dropdown-menu" aria-labelledby="navbarDropdown">
              {createMenu(objMenuItem[key].submenu, true)}
            </div>
          </li>
        )

        tmpArr.push(newString)
      }

      return tmpArr
    }

    let menuSettings = this.props.header.menuSettings
    let newMenu = createMenu(menuSettings, false)

    newMenu.unshift(
      <li className="nav-item active" key='index'>
        <a className="nav-link" href='/'>ГЛАВНАЯ</a>
      </li>
    )

    /**
     * 
     * НЕ РАБОТАЕ ГЕНЕРАЦИЯ МЕНЮ НАДО РАЗБИРАТЬСЯ
     * 
     */

    return (<ul className="navbar-nav mr-auto">{newMenu}</ul>)
  }

  /*render() {
    let objMenuItem = this.props.header.menuSettings
    let menuItems = Object.keys(objMenuItem)

    //          {newMenu}
    return (
      <Navbar bg="light" expand="lg">
        <Nav className="mr-auto">
          <Nav.Link key='index' href='/' className='menu-top-active'>
            ГЛАВНАЯ
          </Nav.Link>
          {menuItems.map(item => {
            let itemsSubmenu = Object.keys(objMenuItem[item].submenu)

            return (itemsSubmenu.length === 0) ? <Nav.Link key={item} href={item}>{objMenuItem[item].name}</Nav.Link> :
              (<NavDropdown key={item}
                title={objMenuItem[item].name}
                id='ddlmenuItem'>
                {itemsSubmenu.map(key => {
                  return (<NavDropdown.item href={key}>
                  {console.log(objMenuItem[item].submenu[key].name)}
                    {objMenuItem[item].submenu[key].name}
                  </NavDropdown.item>)
                })}
              </NavDropdown>)
          })}
        </Nav>
      </Navbar>
    )
  }*/
}

ReactDOM.render(
  <CreateHeaderMenu header={resivedFromServer} />,
  document.getElementById('menu-top')
)
