// models/ProjectDetail.js
import mongoose from "mongoose";

const projectDetailSchema = new mongoose.Schema(
    {

        title: { type: String, required: true }, // e.g. "Tekken 7"

        reports: {

            email: { type: String, default: "N/A" },
            capability: { type: String, default: "Maintain (Keep lights on)" },
            methodology: { type: String, default: "Agile" },
            pillar: { type: String, default: "Organizational & Staff" },
            rockSize: { type: String },
            useCase: { type: String },
            totalHours: { type: Number },
            totalResources: { type: Number },

            summary: { type: String, default: "-" }, // ✅ ADDED SUMMARY FIELD

            tasks: [
                {
                    title: { type: String, required: true },
                    department: { type: String, default: "-" },
                    hours: { type: Number, default: 0 },
                    resources: { type: Number, default: 0 },
                    comment: { type: String, default: "-" },
                },
            ],
        },
    },

    { timestamps: true }
);

export default mongoose.models.ProjectDetail ||
    mongoose.model("ProjectDetail", projectDetailSchema);
