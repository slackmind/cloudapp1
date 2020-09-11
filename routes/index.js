var express = require('express');
var router = express.Router();
const axios = require('axios').default;

router.get('/searchterm', function(req, res) {

  console.log("hello kiki");
  console.log(req.query);
  let keyword = req.query.keyword;
  console.log(keyword);

  /* NIST CVE API URL  */
  const NIST_URL = "https://services.nvd.nist.gov/rest/json/cves/1.0";
  let keywordSearch = `?keyword=${keyword}`;
  let numResults = '&resultsPerPage=5';

  axios
  .get(NIST_URL + keywordSearch + numResults)
    .then((response) => {
          
    const { data } = response;
    })
  
  res.render('searchterm', {
    term: keyword,
    }
  )
});

router.get('/timeframe', function(req, res) {

  console.log(req.query);
  let days = req.query.days;
  let startMonth = req.query.startMonth;
  let startYear = req.query.startYear;
  let endMonth = req.query.endMonth;
  let endYear = req.query.endYear;
  

  /* NIST CVE API URL  */
  const NIST_URL = "https://services.nvd.nist.gov/rest/json/cves/1.0";
  let nistTimeFrame = `?pubStartDate=${startYear}-${startMonth}-01T00:00:00:000 UTC-05:00`;
  let numResults = '&resultsPerPage=5';

  axios
  .get(NIST_URL + nistTimeFrame + numResults)
        
        .then((response) => {
          console.log('got here')

          // save the response to an object
          let { data } = response;
          console.log('attempt to display data');

          // we are just interested in the CVE_Items array
          console.log(data.result.CVE_Items[0].cve.description.description_data[0].value);
          console.log(data.result.CVE_Items[1].cve.description.description_data[0].value);
          let plzwork = data.result.CVE_Items[0].cve.description.description_data[0].value
          // calculate how big the array is
          console.log('how many things? ' + data.result.CVE_Items.length);
          console.log(plzwork);

          res.render('timeframe', { 
            title: 'Update',
            sometext: plzwork, 
            title2: 'Check a file',
            //info: allDescriptions
           });
          
  })

  // error handling
  .catch(err => {
    if (err.response) {
      console.log("5xx/4xx error");
      console.log(err);
    } else if (err.request) {
      console.log("something went wrong with response or request");
      console.log(err);
    }
    console.log(err);
    console.log("something went wrong, axios error");
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
