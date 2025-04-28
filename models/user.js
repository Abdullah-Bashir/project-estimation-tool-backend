import mongoose from "mongoose";

const userSchema = new mongoose.Schema(
    {
        username: { type: String, required: true, unique: true, trim: true },
        email: { type: String, required: true, unique: true, lowercase: true, trim: true },
        password: { type: String, required: true },

        role: { type: String, enum: ["user", "admin"], default: "user" },

        accountVerified: { type: Boolean, default: false },

        verificationCode: { type: Number },
        verificationCodeExpire: { type: Date },

        resetPasswordToken: { type: String, default: null },
        resetPasswordExpire: { type: Date, default: null },

        avatar: { public_id: String, url: String },

        createdAt: { type: Date, default: Date.now },

        provider: {
            type: String,
            enum: ['local', 'google', 'github'],
            default: 'local'
        },
        socialId: String

    },
    { timestamps: true }
);

const User = mongoose.model("User", userSchema);

export default User;

