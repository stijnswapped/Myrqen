/**
 * lab-results/download-consent-form
 *
 * Streams the scanned consent form that an owner signed before a panel was
 * sent off to the lab. Same delivery mechanism as the result PDFs next door.
 */

var path = require('path');
var fs = require('fs');

module.exports = async function downloadConsentForm(req, res) {

  var filename = req.param('filename');
  if (!filename) {
    return res.badRequest(new Error('A `filename` query parameter is required.'));
  }

  // The front-desk scanner files consent forms under a per-day batch folder,
  // so the name we are handed legitimately contains separators and we cannot
  // flatten it to a basename. Resolve it first, then confirm the result is
  // still underneath the store before we open anything.
  var storageRoot = path.resolve(sails.config.custom.consentFormStorageDir);
  var candidatePath = path.resolve(storageRoot, filename);

  if (candidatePath !== storageRoot && !candidatePath.startsWith(storageRoot + path.sep)) {
    sails.log.warn('User ' + req.me.id + ' asked for a consent form outside the store: ' + filename);
    return res.forbidden();
  }

  var labResult = await LabResult.findOne({ consentFormFileName: filename }).populate('patient');
  if (!labResult) {
    return res.notFound();
  }

  // Portal users only get their own household's paperwork; staff only get the
  // paperwork raised by the site they work at.
  if (req.me.role === 'client') {
    if (!req.me.client || labResult.patient.client !== req.me.client) {
      return res.notFound();
    }
  } else if (req.me.clinic.id !== labResult.clinic) {
    return res.notFound();
  }

  if (!fs.existsSync(candidatePath)) {
    return res.notFound();
  }

  res.attachment('consent-' + labResult.id + path.extname(candidatePath));
  return res.sendFile(candidatePath);

};
