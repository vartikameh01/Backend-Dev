'use strict';

/**
 * MedicalRecord.js
 * Task 6: PHI fields (diagnosis, notes, symptoms) stored encrypted.
 * Task 7: Every access logged via auditService.
 */

const mongoose = require('mongoose');
const { encrypt, decrypt } = require('../services/encryptionService');

const medicalRecordSchema = new mongoose.Schema(
  {
    patient:      { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
    doctor:       { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    appointment:  { type: mongoose.Schema.Types.ObjectId, ref: 'Appointment' },

    // Encrypted PHI fields
    _enc_diagnosis:       { type: String },
    _enc_symptoms:        { type: String },
    _enc_notes:           { type: String },
    _enc_treatmentPlan:   { type: String },
    _enc_allergies:       { type: String },
    _enc_medications:     { type: String },

    // Document references (stored names from documentService)
    documents: [
      {
        storedName:   { type: String, required: true },
        originalName: { type: String },
        mimeType:     { type: String },
        sizeBytes:    { type: Number },
        uploadedAt:   { type: Date, default: Date.now },
        uploadedBy:   { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
      },
    ],

    visitDate: { type: Date, required: true },
    isDeleted: { type: Boolean, default: false }, // soft-delete for audit trail
  },
  {
    timestamps: true,
    toJSON:   { virtuals: true, transform: (doc, ret) => { delete ret.__v; return ret; } },
    toObject: { virtuals: true },
  }
);

// Encrypted virtual fields
function makeEncryptedVirtual(name) {
  medicalRecordSchema.virtual(name)
    .get(function () {
      if (!this[`_enc_${name}`]) return undefined;
      try { return decrypt(this[`_enc_${name}`]); } catch { return undefined; }
    })
    .set(function (val) {
      this[`_enc_${name}`] = val ? encrypt(String(val)) : undefined;
    });
}

['diagnosis', 'symptoms', 'notes', 'treatmentPlan', 'allergies', 'medications']
  .forEach(makeEncryptedVirtual);

// Soft-delete query helper — exclude deleted records by default
medicalRecordSchema.pre(/^find/, function () {
  if (this.getFilter().isDeleted === undefined) {
    this.where({ isDeleted: false });
  }
});

const MedicalRecord = mongoose.model('MedicalRecord', medicalRecordSchema);
module.exports = MedicalRecord;
