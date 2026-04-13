'use strict';

/**
 * Prescription.js
 * Task 2: Prescription content stored as encrypted PHI.
 */

const mongoose = require('mongoose');
const { encrypt, decrypt } = require('../services/encryptionService');

const prescriptionSchema = new mongoose.Schema(
  {
    patient:     { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
    doctor:      { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    appointment: { type: mongoose.Schema.Types.ObjectId, ref: 'Appointment' },

    // All prescription fields are PHI — encrypted at rest
    _enc_medicationName: { type: String, required: true },
    _enc_dosage:         { type: String },
    _enc_frequency:      { type: String },
    _enc_duration:       { type: String },
    _enc_instructions:   { type: String },
    _enc_refills:        { type: String },

    issuedDate:  { type: Date, default: Date.now },
    expiryDate:  { type: Date },
    isActive:    { type: Boolean, default: true },
  },
  {
    timestamps: true,
    toJSON:   { virtuals: true, transform: (doc, ret) => { delete ret.__v; return ret; } },
    toObject: { virtuals: true },
  }
);

['medicationName', 'dosage', 'frequency', 'duration', 'instructions', 'refills'].forEach((name) => {
  prescriptionSchema.virtual(name)
    .get(function () {
      if (!this[`_enc_${name}`]) return undefined;
      try { return decrypt(this[`_enc_${name}`]); } catch { return undefined; }
    })
    .set(function (val) {
      this[`_enc_${name}`] = val ? encrypt(String(val)) : undefined;
    });
});

const Prescription = mongoose.model('Prescription', prescriptionSchema);
module.exports = Prescription;
