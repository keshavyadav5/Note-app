import React from 'react'
import { getInitials } from '../utils/helper'

const ProfileInfo = ({ onLogOut, userInfo }) => {
  return (
    <div className='flex gap-3 items-center'>
      <div className='w-11 h-11 flex items-center justify-center rounded-full text-slate-950 font-medium bg-slate-100'>
        {
          getInitials(userInfo?.username)
        }
      </div>
      <div className='hidden sm:block'>
        <p className='text-sm font-medium'>{userInfo?.username}</p>
      </div>
      <div>
        <button className='text-sm bg-red-500 p-1 rounded-md text-white hover:opacity-80'
          onClick={onLogOut}
        >Logout</button>
      </div>
    </div>
  )
}

export default ProfileInfo