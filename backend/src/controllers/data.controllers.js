import mongoose from "mongoose";
import Datas from "../models/data.models.js";
import { v2 as cloudinary } from 'cloudinary';
import fs from "fs";
import dotenv from "dotenv";
dotenv.config();


cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET
});


const uploadImageToCloudinary = async (localPath) => {
  try {
    const result = await cloudinary.uploader.upload(localPath, {
      resource_type: "auto",
    });
    fs.unlinkSync(localPath);
    return result.url;
  } catch (err) {
    return fs.unlinkSync(localPath);
  };
};


const uploadImage = async (req, res) => {
  if (!req.file) return res.status(400).json({
    message: "no image file uploaded",
  });

  try {
    const uploadResult = await uploadImageToCloudinary(req.file.path);
    if (!uploadResult) return res.status(500).json({
      message: "error occured while uploading image"
    });

    res.json({
      message: "image uploaded successfully",
      url: uploadResult,
    });
  }
  catch (error) {
    console.log(error);
    res.status(500).json({ message: "error occured while uploading image" });
  }
}


const addData = (req, res) => {
  const { title, description } = req.body;

  if (!title || !description) {
    res.status(400).json({
      message: "title or description required",
    });
    return;
  }

  const data = Datas.create({
    title,
    description,
  });
  res.status(201).json({
    message: "data added to database successfully",
  });
};



const getAllDatas = async (req, res) => {
  const datas = await Datas.find({});
  res.status(200).json({
    datas: datas,
  });
};

const getDataWithId = async (req, res) => {
  const { id } = req.params;

  if (!mongoose.Types.ObjectId.isValid(id)) {
    return res.status(400).json({ error: "Not valid Id" });
  }

  const data = await Datas.findById(id);
  if (!data) {
    res.status(404).json({
      message: "no data found!",
    });
    return;
  }

  res.status(200).json(todo);
};



const deleteData = async (req, res) => {
  const { id } = req.params;

  if (!mongoose.Types.ObjectId.isValid(id)) {
    return res.status(400).json({ error: "Not valid id" });
  }

  const data = await Datas.findOneAndDelete({ _id: id });

  if (!data) {
    return res.status(404).json({ error: "No data found" });
  }
  res.status(200).json({
    message: "data deleted successfully",
    data,
  });
};




const editData = async (req, res) => {
  const { id } = req.params;
  const { title, description, completed } = req.body;

  if (!mongoose.Types.ObjectId.isValid(id)) {
    return res.status(400).json({ error: "Invalid ID" });
  }
  try {
    const updatedData = await Datas.findOneAndUpdate(
      { _id: id },
      { title, description, completed },
      { new: true, runValidators: true }
    );

    if (!updatedData) {
      return res.status(404).json({ error: "No data found" });
    }

    res.status(200).json({
      message: "Data updated successfully",
      data: updatedData,
    });
  } catch (error) {
    res.status(500).json({ error: "Something went wrong", details: error.message });
  }
};

export { addData , getAllDatas , getDataWithId , deleteData , editData , uploadImage };