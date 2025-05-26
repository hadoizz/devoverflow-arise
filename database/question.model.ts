import { Schema, models, model, Document } from "mongoose";

export interface IQuestion {
  title: string;
  content: string;
  tags: string[]; // or Types.ObjectId[] if tags are ObjectIds
  views: number;
  answers: number;
  upvotes: number;
  downvotes: number;
  author: string; // <- updated to String for UUID support
}

export interface IQuestionDoc extends IQuestion, Document {}

const QuestionSchema = new Schema<IQuestion>(
  {
    title: { type: String, required: true },
    content: { type: String, required: true },
    tags: [{ type: Schema.Types.ObjectId, ref: "Tag" }], // keep as ObjectId if Tag uses ObjectId
    views: { type: Number, default: 0 },
    answers: { type: Number, default: 0 },
    upvotes: { type: Number, default: 0 },
    downvotes: { type: Number, default: 0 },
    author: { type: String, ref: "User", required: true }, // <- fixed
  },
  { timestamps: true }
);

const Question = models?.Question || model<IQuestion>("Question", QuestionSchema);

export default Question;
