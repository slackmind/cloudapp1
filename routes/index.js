var express = require('express');
var router = express.Router();
const axios = require('axios').default;

router.get('/search', function(req, res) {

  console.log(req.query);
  let days = req.query.days;
  let startMonth = req.query.startMonth;
  let endMonth = req.query.endMonth;
  let startYear = req.query.startYear;
  let endYear = req.query.endYear;

  /* NIST CVE API URL  */
  const NIST_URL = "https://services.nvd.nist.gov/rest/json/cves/1.0";
  let nistTimeFrame = `?pubStartDate=${startYear}-${startMonth}-01T00:00:00:000 UTC-05:00`;
  let numResults = '&resultsPerPage=5';

  axios
  .get(NIST_URL + nistTimeFrame + numResults)
        
        .then((response) => {
          console.log('got here')
          let { data } = response;
          //console.log(data[0])
          let allDescriptions = data.result.CVE_Items[0].cve.description.description_data.value;

          console.log(allDescriptions);


})
});

/* GET home page. */
router.get('/', function(req, res) {

  res.render('index', { 
    title: 'Recent Vulnerabilities', 
    title2: 'Check a file',
    //info: allDescriptions
   });
});


router.post('/', function (req, res) {
  console.log(req.body.selectDays);
  console.log(req.body.description);
  res.send('Post page');
});

module.exports = router;
