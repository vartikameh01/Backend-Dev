'use strict';

/**
 * Appointment.js
 * Stores scheduling data. The appointment reason is mildly sensitive
 * so it is stored encrypted as well.
 */

const mongoose = require('mongoose');
const { encrypt, decrypt } = require('../services/encryptionService');

const STATUS = ['scheduled', 'confirmed', 'cancelled', 'completed', 'no_show'];

const appointmentSchema = new mongoose.Schema(
  {
    patient:  { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
    doctor:   { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
    appointmentDate: { type: Date, required: true },
    durationMinutes: { type: Number, default: 30, min: 10, max: 240 },
    status: {
      type: String,
      enum: STATUS,
      default: 'scheduled',
    },
    // Encrypted — patient's reason for visit is PHI
    _enc_reason: { type: String },
    // Non-sensitive scheduling metadata
    isVirtual:    { type: Boolean, default: false },
    meetingLink:  { type: String },
    cancelledBy:  { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    cancellationNote: { type: String, maxlength: 500 },
  },
  {
    timestamps: true,
    toJSON:   { virtuals: true, transform: (doc, ret) => { delete ret.__v; return ret; } },
    toObject: { virtuals: true },
  }
);

appointmentSchema.virtual('reason')
  .get(function () {
    if (!this._enc_reason) return undefined;
    try { return decrypt(this._enc_reason); } catch { return undefined; }
  })
  .set(function (val) {
    this._enc_reason = val ? encrypt(String(val)) : undefined;
  });

const Appointment = mongoose.model('Appointment', appointmentSchema);
module.exports = Appointment;
