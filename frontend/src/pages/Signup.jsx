import axios from 'axios'
import React, { useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { toast } from 'react-toastify'
import {ENV} from '../config/env'

const Signup = () => {
  const [name, setName] = useState("")
  const [email, setEmail] = useState("")
  const [password, setPassword] = useState("")
  const [error, setError] = useState("")
  const navigate = useNavigate()

  const handleOnSubmit = async (e) => {
    e.preventDefault()

    try {
      const res = await axios.post(`${ENV.BACKEND_URL}/api/auth/signup`, {
        username: name, email, password
      }, {
        withCredentials: true
      })
      if(res.data.success === false){
        toast.error(res.data.message)
      }
      toast.success(res.data.message)
      navigate('/login')
    } catch (error) {
      toast.error(error.message)
      console.log(error.message);
      setError(error.message)
    }
  }
  return (
    <div className='flex items-center justify-center mt-28'>
      <div className='w-96 border rounded bg-white px-7 py-10'>
        <form onSubmit={handleOnSubmit}>
          <h4 className='text-2xl mb-7'>Login</h4>

          <input
            type="text"
            placeholder="Name"
            className='input-box'
            value={name}
            autoFocus
            required
            onChange={(e) => setName(e.target.value)}
          />

          <input
            type="email"
            placeholder="Email"
            className='input-box'
            value={email}
            required
            onChange={(e) => setEmail(e.target.value)}
          />

          <input type="password"
            placeholder="Password"
            className='input-box'
            value={password}
            required
            onChange={(e) => setPassword(e.target.value)}
          />

          <button type='submit' className='btn-primary'>SIGN UP</button>

          <p className='text-sm text-center mt-4'>
            Already have an account? {" "}
            <Link to={'/login'} className="font-medium text-primary underline">login</Link>
          </p>
        </form>
      </div>
    </div>
  )
}


export default Signup