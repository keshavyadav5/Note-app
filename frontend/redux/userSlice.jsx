import { createSlice } from '@reduxjs/toolkit'

const initialState = {
  currentUser: null,
  errorDispatch: null,
  loading: false
}

const userSlice = createSlice({
  name: 'user',
  initialState,
  reducers: {
    loginStart: (state) => {
      state.loading = true
    },
    loginSuccess: (state, action) => {
      state.currentUser = action.payload;
      state.errorDispatch = null;
      state.loading = false;
    },
    loginFailure: (state, action) => {
      state.errorDispatch = action.payload;
      state.loading = false;
    },
    signoutStart : (state) =>{
      state.loading = true
    },
    signoutSuccess : (state) =>{
      state.currentUser = null,
      state.errorDispatch = null,
      state.loading = false
    },
    signoutFailure: (state,action) =>{
      state.errorDispatch = action.payload;
      state.loading = false;
    }
  }
})

export const { loginStart, loginSuccess, loginFailure, signoutFailure, signoutStart, signoutSuccess } = userSlice.actions

export default userSlice.reducer;