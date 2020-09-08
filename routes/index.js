var express = require('express');
var router = express.Router();

let selectDays = []

/* GET home page. */
router.get('/', function(req, res) {

  console.log(req.query);
  let days = req.query.days;

  
  res.render('index', { 
    title: 'Recent Vulnerabilities', 
    title2: 'Check a file',
   });
});


router.post('/', function (req, res) {
  console.log(req.body.selectDays);
  console.log(req.body.description);
  res.send('Post page');
});

module.exports = router;
