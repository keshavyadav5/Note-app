import React, { useEffect, useState } from 'react';
import NoteCard from '../components/NoteCard';
import { MdAdd } from 'react-icons/md';
import Modal from 'react-modal';
import AddEditNotes from './AddEditNotes';
import { useSelector } from 'react-redux';
import { useNavigate } from 'react-router-dom';
import Navbar from '../components/Navbar';
import axios from 'axios';
import { toast } from 'react-toastify';
import EmptyCard from '../components/EmptyCard';
import { ENV } from '../config/env';


const Home = () => {
  const { currentUser, loading, errordispatch } = useSelector((state) => state.user);
  const navigate = useNavigate();
  const [userInfo, setUserInfo] = useState(null);
  const [allNotes, setAllNotes] = useState([]);
  const [isSearched, setIsSearched] = useState(false)

  const [openAddEditModel, setOpenEditModel] = useState({
    isShown: false,
    type: 'add',
    data: null,
  });

  useEffect(() => {
    if (!currentUser) {
      navigate('/login');
    } else {
      setUserInfo(currentUser?.userData);
      getAllNotes();
    }
  }, [currentUser, navigate]);

  const getAllNotes = async () => {
    try {
      const res = await axios.get(`${ENV.BACKEND_URL}/api/note/all`, {
        withCredentials: true,
      });
      if (res.data.success === false) {
        toast.error(res.data.message);
        console.log(res.data);
        return;
      }
      setAllNotes(res.data.notes);
    } catch (error) {
      toast.error(`Error fetching notes: ${error.message}`);
      console.log(error);
    }
  };

  const handleEdit = (noteDetails) => {
    setOpenEditModel({ isShown: true, data: noteDetails, type: 'edit' });
  };

  const deleteNote = async (note) => {
    const noteId = note._id;
    try {
      const res = await axios.delete(`${ENV.BACKEND_URL}/api/note/delete/${noteId}`, {
        withCredentials: true,
      });

      if (!res.data.success) {
        toast.error(`Failed to delete note: ${res.data.message}`);
        return;
      }

      toast.success('Note deleted successfully!');
      setAllNotes(allNotes.filter((n) => n._id !== noteId));
    } catch (error) {
      console.log(error);
      toast.error(`Error deleting note: ${error.message}`);
    }
  };

  const onSearchNote = async (query) => {
    if (!query || query.trim() === '') {
      toast.warning('Please enter a valid search query.');
      return;
    }

    try {
      const res = await axios.get(`${ENV.BACKEND_URL}/api/note/search`, {
        params: { query }, 
        withCredentials: true,
      });

      if (!res.data.success) {
        toast.error(`Search failed: ${res.data.message}`);
        return;
      }
      setIsSearched(true)
      setAllNotes(res.data.notes);
      toast.success('Notes fetched successfully!');
    } catch (error) {
      console.log(error);
      toast.error(`Error fetching notes: ${error.message}`);
    }
  };

  const handleClearSearch = () => {
    setIsSearched(false)
    getAllNotes();
    toast.info('Search cleared, displaying all notes.');
  };

  const updateIsPinned = async (noteData) => {
    const noteId = noteData._id;
    try {
      const res = await axios.put(`${ENV.BACKEND_URL}/api/note/update-note-pinned/${noteId}`, {
        isPinned: !noteData.isPinned
      }, { withCredentials: true })

      if (!res.data.success) {
        toast.error(`Failed to update note: ${res.data.message}`)
      }
      toast.success(res.data.message)
      getAllNotes()
    } catch (error) {
      console.log(error.message);
      toast.error(error.message)
    }
  }

  return (
    <>
      <Navbar userInfo={userInfo} handleClearSearch={handleClearSearch} onSearchNote={onSearchNote} />
      <div className='container mx-auto'>
        {
          allNotes?.length > 0 ? (
            <div className='grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 gap-4 mt-8 max-md:m-5'>
              {allNotes.map((note, index) => (
                <NoteCard
                  key={note._id}
                  title={note.title}
                  date={note.createdAt}
                  content={note.content}
                  tags={note.tags}
                  isPinned={note.isPinned}
                  onEdit={() => {
                    handleEdit(note);
                  }}
                  onDelete={() => {
                    deleteNote(note); 
                  }}
                  onPinNote={() => {
                    updateIsPinned(note);
                  }}
                />
              ))}
            </div>
          ) : (
            <EmptyCard isSearched={isSearched} />
          )
        }
      </div>
      <button
        className='w-16 h-16 flex items-center justify-center rounded-2xl bg-primary hover:bg-blue-600 absolute right-10 bottom-10'
        onClick={() =>
          setOpenEditModel({ isShown: true, type: 'add', data: null })
        }
      >
        <MdAdd className='text-[32px] text-white' />
      </button>
      <Modal
        isOpen={openAddEditModel.isShown}
        onRequestClose={() => { }}
        style={{
          overlay: {
            backgroundColor: 'rgba(0,0,0,0.2)',
          },
        }}
        contentLabel=''
        className='w-[40%] max-md:w-[60%] max-sm:w-[70%] max-h-3/4 bg-white rounded-md mx-auto mt-14 p-5 overflow-scroll'
      >
        <AddEditNotes
          onClose={() => setOpenEditModel({ isShown: false, type: 'add', data: null })}
          noteData={openAddEditModel.data}
          type={openAddEditModel.type}
          getAllNotes={getAllNotes}
        />
      </Modal>
    </>
  );
};

export default Home;
