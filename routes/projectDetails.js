import express from "express";
import ProjectDetail from "../models/projectDetails.js";

const router = express.Router();

// Backend route for creating or updating project
router.post("/", async (req, res) => {
    try {
        const { _id, ...rest } = req.body;  // Extract _id and rest of the fields
        let project;

        if (_id) {
            // If _id exists, update the project
            project = await ProjectDetail.findByIdAndUpdate(_id, rest, {
                new: true,  // Return the updated project
                runValidators: true,  // Validate before saving
            });
            if (!project) return res.status(404).json({ success: false, message: "Project not found" });
        } else {
            // If _id doesn't exist, create a new project
            project = await ProjectDetail.create(req.body);
        }

        res.status(201).json({ success: true, data: project });
    } catch (error) {
        console.error("Error creating/updating project:", error);
        res.status(500).json({ success: false, message: error.message });
    }
});

// ✅ Get all projects
router.get("/", async (req, res) => {
    try {
        const projects = await ProjectDetail.find().sort({ createdAt: -1 });
        res.status(200).json({ success: true, data: projects });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
});

// ✅ Get single project by ID
router.get("/:id", async (req, res) => {
    try {
        const project = await ProjectDetail.findById(req.params.id);
        if (!project) return res.status(404).json({ success: false, message: "Project not found" });

        res.status(200).json({ success: true, data: project });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
});

// ✅ Update project by ID
router.put("/:id", async (req, res) => {
    try {
        const updated = await ProjectDetail.findByIdAndUpdate(req.params.id, req.body, {
            new: true,
            runValidators: true,
        });

        if (!updated) return res.status(404).json({ success: false, message: "Project not found" });

        res.status(200).json({ success: true, data: updated });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
});

// ✅ DELETE project by ID
router.delete("/:id", async (req, res) => {
    try {
        const deleted = await ProjectDetail.findByIdAndDelete(req.params.id);
        if (!deleted) return res.status(404).json({ success: false, message: "Project not found" });

        res.status(200).json({ success: true, message: "Project deleted successfully" });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
});

export default router;
