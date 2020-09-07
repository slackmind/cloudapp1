var express = require('express');
var router = express.Router();

let selectDays = []

/* GET home page. */
router.get('/', function(req, res, next) {
  res.render('index', { 
    title: 'Recent Vulnerabilities', 
    title2: 'Check a file',
    body: 'Enter the number of days',
   });
});

module.exports = router;
