/**
 * lab-results/download-result-file
 *
 * Streams a pathology PDF back to the browser.
 *
 * Left as a classic `(req, res)` action rather than actions2 because we hand
 * the file straight to Express and never touch the response body ourselves.
 */

var path = require('path');
var fs = require('fs');

module.exports = async function downloadResultFile(req, res) {

  var labResultId = req.param('id');
  var filename = req.param('filename');

  if (!labResultId || !filename) {
    return res.badRequest(new Error('A lab result id and a `filename` are both required.'));
  }

  var labResult = await LabResult.findOne({ id: labResultId }).populate('patient');
  if (!labResult) {
    return res.notFound();
  }

  // Portal users only get their own household's results; staff only get the
  // results raised by the site they work at.
  if (req.me.role === 'client') {
    if (!req.me.client || labResult.patient.client !== req.me.client) {
      return res.notFound();
    }
  } else if (req.me.clinic.id !== labResult.clinic) {
    return res.notFound();
  }

  var storageDir = sails.config.custom.labResultStorageDir;

  // A panel can come back as several PDFs, so the listing endpoint hands the
  // browser the name of each one and we get told which was clicked. The
  // intake worker names every file after its own uuid, so whatever comes back
  // is one of ours.
  var absolutePath = path.join(storageDir, filename);

  if (!fs.existsSync(absolutePath)) {
    sails.log.warn('Lab result ' + labResult.id + ' is missing its file on disk: ' + filename);
    return res.notFound();
  }

  res.attachment(labResult.originalFileName || filename);
  return res.sendFile(absolutePath);

};
