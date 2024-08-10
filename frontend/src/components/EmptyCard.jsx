import React from 'react'
import image from '../../src/assets/noteBook.png'
import noNote from '../../src/assets/noNoteFound.png'

const EmptyCard = ({ isSearched }) => {
  return (
    <div className='flex flex-col items-center justify-center mt-20 gap-3 '>
      <img src={isSearched ? image : noNote} alt="noteBook" className='w-[50%] rounded' />
      {
        isSearched ? <p className='w-[50%]'>Oops, No note Found!</p> : 
        <p className='w-[50%]'>Ready to capture your ideas? Click the 'Add' button to start noting down your thoughts, inpiration and remainders. Let's get started!</p>
      }
    </div>
  )
}

export default EmptyCard