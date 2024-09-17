import React, { useState } from 'react'
import SearchBar from './SearchBar'
import ProfileInfo from './ProfileInfo'
import { Link, useNavigate } from 'react-router-dom'
import { useDispatch } from 'react-redux'
import { signoutFailure, signoutStart, signoutSuccess } from '../../redux/userSlice'
import axios from 'axios'
import { toast } from 'react-toastify'

const Navbar = ({ userInfo, handleClearSearch, onSearchNote }) => {
  const navigate = useNavigate()
  const dispatch = useDispatch()

  const [searchQuery, setSearchQuery] = useState("");
  const handleSearch = () => {
    if(searchQuery){
      onSearchNote(searchQuery)
    }
  }
  const onClearSearch = () => {
    setSearchQuery("")
    handleClearSearch()
  }

  const onLogOut = async () => {
    try {
      dispatch(signoutStart())

      const res = await axios.get('https://note-app-backend-dqfa.onrender.com/api/auth/logout', {
        withCredentials: true
      })

      if (res.data.success === false) {
        dispatch(signoutFailure(res.data.message))
        toast.error(res.data.message)
      }
      toast.success(res.data.success)
      dispatch(signoutSuccess())
      navigate("/login")
    } catch (error) {
      toast.error(error.message)
      dispatch(signoutFailure())
    }
  }
  return (
    <div className='bg-white flex  items-center justify-between px-6 py-2 drop-shadow'>
      <Link to={'/'}>
        <h2 className='text-xl text-black py-2 font-medium'>
          <span className='text-slate-500'>my</span>
          <span className='text-slate-900'>Notes</span>
        </h2>
      </Link>

      <SearchBar
        value={searchQuery}
        onChange={({ target }) => setSearchQuery(target.value)}
        handleSearch={handleSearch}
        onClearSearch={onClearSearch}
      />

      <ProfileInfo userInfo={userInfo} onLogOut={onLogOut} />
    </div>
  )
}

export default Navbar