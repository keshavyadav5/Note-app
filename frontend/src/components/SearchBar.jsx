import React from 'react'
import { BiSearch } from "react-icons/bi";
import { RxCross2 } from "react-icons/rx";


const SearchBar = ({value, onChange, onClearSearch, handleSearch}) => {
  return (
    <div 
    className='bg-slate-100 flex items-center pr-2 w-40 container rounded md:w-80 sm:w-60'>

      <input type="text"
        placeholder="Search..."
        className=' w-full outline-none bg-transparent p-2'
        value={value}
        onChange={onChange}
      />

      {
        value && <RxCross2 className='text-slate-500 text-xl cursor-pointer hover:text-black mr-1'
          onClick={onClearSearch}
        />
      }
      <BiSearch  className='text-slate-600 text-xl cursor-pointer hover:text-black'
        onClick={handleSearch}
      />

    </div>
  )
}

export default SearchBar