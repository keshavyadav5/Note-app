import React, { useState } from 'react'
import { useDispatch, useSelector } from 'react-redux'
import { Link, useNavigate } from 'react-router-dom'
import { loginFailure, loginStart, loginSuccess } from '../../redux/userSlice'
import axios from 'axios'
import { toast } from 'react-toastify'

const Login = () => {
  const [email, setEmail] = useState("")
  const [password, setPassword] = useState("")
  const [error, setError] = useState("")

  const dispatch = useDispatch()
  const navigate = useNavigate()
  

  const handleOnSubmit = async (e) => {
    e.preventDefault()

    try {
      dispatch(loginStart())
      const res = await axios.post('https://note-app-backend-dqfa.onrender.com/api/auth/login', {
        email,
        password
      }, { withCredentials: true })

      if(res.data.success === false){
        toast.error(res.data.error)
        console.log(res.data);
        dispatch(loginFailure(data.message))
      }
      toast.success(res.data.message)
      dispatch(loginSuccess(res.data))
      navigate('/')
    } catch (error) {
      toast.error(error.message)
      console.log(error);
      dispatch(loginFailure(error.message))
    }
  }
  return (
    <div className='flex items-center justify-center mt-28'>
      <div className='w-96 border rounded bg-white px-7 py-10'>
        <form onSubmit={handleOnSubmit}>
          <h4 className='text-2xl mb-7'>Login</h4>
          <input
            type="email"
            placeholder="Email"
            className='input-box'
            value={email}
            autoFocus
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

          <button type='submit' className='btn-primary'>LOGIN</button>

          <p className='text-sm text-center mt-4'>
            Not registerd yet? {" "}
            <Link to={'/signup'} className="font-medium text-primary underline">Create an account</Link>
          </p>
        </form>
      </div>
    </div>
  )
}

export default Login