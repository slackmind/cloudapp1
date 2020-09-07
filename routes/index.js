var express = require('express');
var router = express.Router();

/* GET home page. */
router.get('/', function(req, res, next) {
  res.render('index', { 
    title: 'Check Dates', 
    title2: 'Check IP Address',
    body: 'Enter the number of days',
    body2: 'Second Body' });
});

module.exports = router;
