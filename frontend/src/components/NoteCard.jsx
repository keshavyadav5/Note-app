import React from 'react'
import { MdOutlinePushPin, MdCreate, MdDelete } from "react-icons/md";
import moment from 'moment'

const NoteCard = ({ date, title, content, isPinned, onPinNote, onEdit, onDelete, tags }) => {
  return (
    <div className='border rounded p-4 bg-white hover:shadow-xl transition-all ease-in-out'>

      <div className='flex items-center justify-between'>

        <div>
          <h6 className='text-sm font-medium'>
            {title}
          </h6>
          <span className='text-xs text-green-700'>
            {moment(date).format("DD MM YYYY")}
          </span>
        </div>
        <MdOutlinePushPin
          className={`icon-btn ${isPinned ? "text-primary" : 'text-slate-300'}`}
          onClick={onPinNote}
        />

      </div>
      <p className='text-xs text-slate-600 mt-2'>
        {content?.slice(0, 60)}
      </p>

      <div className='flex items-center justify-between mt-2'>
        <div className='text-xs text-slate-800'>
          {tags.map((item) => `#${item} `)}
        </div>
        <div className='flex items-center gap-2'>
          <MdCreate className='icon-btn hove:text-green-600' onClick={onEdit} />

          <MdDelete className='icon-btn hover:text-red-600' onClick={onDelete} />
        </div>
      </div>

    </div>
  )
}

export default NoteCard