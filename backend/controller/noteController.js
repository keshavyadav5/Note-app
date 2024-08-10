const Note = require('../modules/noteModel');
const { errorHandler } = require('../utils/error');

const addNote = async (req, res, next) => {
  const { title, content, tags } = req.body;

  if (!title) {
    return next(errorHandler(400, "Title is required"))
  }
  if (!content) {
    return next(errorHandler(400, "Content is required"))
  }

  const userId = req.user && req.user.id; 

  if (!userId) {
    return next(errorHandler(401, "User ID is required"));
  }
  try {
    const note = new Note({
      title,
      content,
      tags: tags || [],
      userId: userId
    })
    await note.save()
    res.status(201).json({
      success: true,
      message: "Note added successfully",
      note
    })

  } catch (error) {
    next(error)
  }
}


const editNote = async (req,res,next) => { 
  const note = await Note.findById(req.params.noteId)

  if(!note){
    return next(errorHandler(404,"Note not found"))
  }

  if(req.user.id !== note.userId){
    return next(errorHandler(401, "You can only update your own note"))
  }

  const { title, content, tags, isPinned } = req.body
  if(!title && !content && !tags){
    return next(errorHandler(404,"No changes provided"))
  }

  try {
    if(title){
      note.title = title
    }
    if(content){
      note.content = content
    }
    if(tags){
      note.tags = tags
    }
    if(isPinned){
      note.isPinned = isPinned
    }
    await note.save()
    res.status(200).json({
      success: true,
      message : "Note updated successfully",
      note
    })
  } catch (error) {
    next(error)
  }
}

const getAllNotes = async (req,res,next) =>{
  const userId = req.user.id;

  try {
    const notes = await Note.find({userId : userId}).sort({isPinned : -1})

    res.status(200).json({
      success: true,
      message : "Notes fetched successfully",
      notes
    })
  } catch (error) {
    next(error)
  }
}

const deleteNote = async (req,res,next) =>{
  const noteId = req.params.noteId

  const note = await Note.findOne({_id: noteId, userId: req.user.id})
  if(!note){
    return next(errorHandler(404,"NoteId not found"))
  }

  try {
    await Note.deleteOne({_id: noteId, userId: req.user.id})
    res.status(200).json({
      success : true,
      message : "Note deleted successfully",
    })
  } catch (error) {
    next(error)
  }
}

const updatePinnedNote = async (req,res,next) =>{
  try {
    const note = await Note.findById(req.params.noteId)

    if(!note){
      return next(errorHandler(404,"Note not found"))
    }

    if(req.user.id !== note.userId){
      return next(errorHandler(401,"You can only update your own note!"))
    }

    const {isPinned} = req.body;
    note.isPinned = isPinned
    await note.save()
    res.status(200).json({
      success : true,
      message: "Note is updated successfully",
      note
    })
  } catch (error) {
    next(error)
  }
}
const searchNote = async (req, res, next) => {
  const { query } = req.query; 

  if (!query) {
    return next(errorHandler(400, "Search query is required"));
  }

  try {
    const matchingNotes = await Note.find({
      userId: req.user.id,
      $or: [
        { title: { $regex: query, $options: 'i' } },
        { content: { $regex: query, $options: 'i' } },
      ]
    });
    
    res.status(200).json({
      success: true,
      message: "Notes found",
      notes: matchingNotes
    });
  } catch (error) {
    next(error);
  }
};


exports.addNote = addNote
exports.editNote = editNote
exports.getAllNotes = getAllNotes
exports.deleteNote = deleteNote
exports.updatePinnedNote = updatePinnedNote
exports.searchNote = searchNote