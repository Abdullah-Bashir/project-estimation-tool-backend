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
            rockSize: { type: String, required: true },
            useCase: { type: String, required: true },
            totalHours: { type: Number, required: true },
            totalResources: { type: Number, required: true },

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
