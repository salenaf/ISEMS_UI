import React from 'react'
import ReactDOM from 'react-dom'

class CreateHeaderMenu extends React.Component {
  constructor(props) {
    super(props)
  }

  render() {
    let createMenu = function (objMenuItem, isDropDown) {
      let linkIsDisabled = 'false'

      let classLi = (isDropDown) ? 'nav-item dropdown' : 'nav-item'
      let classA = (isDropDown) ? 'dropdown-item' : 'nav-link'
      let tmpArr = []
      for (let key in objMenuItem) {
        let submenuIsExist = (typeof objMenuItem[key].submenu === 'undefined')

        if ((typeof objMenuItem[key].status !== 'undefined') && (!objMenuItem[key].status)) {
          classA += ' disabled'
          linkIsDisabled = 'true'
        }

        if (submenuIsExist) {
          if (isDropDown) {
            tmpArr.push(
              <a className={classA} key={key} href={key} aria-disabled={linkIsDisabled}>{objMenuItem[key].name}</a>
            )
            continue
          } else {
            tmpArr.push(
              <li className={classLi} key={key}>
                <a className={classA} href={key} aria-disabled={linkIsDisabled}>{objMenuItem[key].name.toUpperCase()}</a>
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
            >{objMenuItem[key].name.toUpperCase()}</a>
            <div className="dropdown-menu" aria-labelledby="navbarDropdownMenuLink">
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
      <li className="nav-item" key='index'>
        <a className="nav-link" href='/'>ГЛАВНАЯ</a>
      </li>
    )

    return (
      <nav className="navbar navbar-expand-lg navbar-light bg-light">
        <div className="collapse navbar-collapse">
          <ul className="navbar-nav mr-auto">{newMenu}</ul>
        </div>
      </nav >)
  }
}

ReactDOM.render(
  <CreateHeaderMenu header={resivedFromServer} />,
  document.getElementById('menu-top')
)
