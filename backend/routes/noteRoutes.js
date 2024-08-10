const express = require('express')
const { verifyToken } = require('../utils/verifyUser')
const { addNote, editNote, getAllNotes, deleteNote, updatePinnedNote, searchNote } = require('../controller/noteController')
const router = express.Router()


router.post('/add',verifyToken,addNote)
router.post('/edit/:noteId',verifyToken,editNote)
router.get('/all',verifyToken,getAllNotes)
router.delete('/delete/:noteId',verifyToken,deleteNote)
router.put('/update-note-pinned/:noteId',verifyToken,updatePinnedNote)
router.get('/search',verifyToken,searchNote)

module.exports = router