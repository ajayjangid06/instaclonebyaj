import React,{useContext} from 'react'
import {Link, useHistory} from 'react-router-dom'
import { UserContext } from '../App'

const NavBar = ()=>{
    const {state,dispatch} = useContext(UserContext)
    const history = useHistory()
    const renderList = () =>{
        if(state){
            return[
                <li><Link to="/profile">Profile</Link></li>,
                <li><Link to="/createpost">Create Post</Link></li>,
                <li><Link to="/myfollowingpost">My Following Posts</Link></li>,
                <li>
                    <button className="btn ##c62828 red darken-3"
                    onClick={()=>{
                        localStorage.clear()
                        dispatch({type:"CLEAR"})
                        history.push('/signin')
                    }}
                    >
                    Sign Out
                </button>
                </li>
            ]
        }else{
            return[
                <li><Link to="/signin">SignIn</Link></li>,
                <li><Link to="/signup">SignUp</Link></li>
            ]

        }
    }

    return(
        <nav>
            <div className="nav-wrapper white">
                <Link to={state?"/":"/signin"} className="brand-logo left">Instagram</Link>
                    <ul id="nav-mobile" className="right">
                        {renderList()}
                    </ul>
            </div>
        </nav>
    )
}


export default NavBar