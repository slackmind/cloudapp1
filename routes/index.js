var express = require('express');
var router = express.Router();
const axios = require('axios').default;

router.get('/searchterm', function(req, res) {

  console.log(req.query);
  let keyword = req.query.keyword;
  let resultNum = req.query.resultNum;
  console.log(keyword);
  console.log("you earched for " +req.query.keyword +" and wanted " + 
  req.query.resultNum+ "results");
  

  /* NIST CVE API URL  */
  const NIST_URL = "https://services.nvd.nist.gov/rest/json/cves/1.0";
  let keywordSearch = `?keyword=${keyword}`;
  let numResults = `&resultsPerPage=${resultNum}`;

  axios
  .get(NIST_URL + keywordSearch + numResults)
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
    let itemsarr = data.result.CVE_Items;
    console.log('how many things? ' + data.result.CVE_Items.length);
    console.log(plzwork);

    res.render('searchterm', { 
      searchedFor: keyword,
      sometext: itemsarr, 
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

router.get('/timeframe', function(req, res) {

  console.log(req.query);
  let days = req.query.days;
  let startMonth = req.query.startMonth;
  let startYear = req.query.startYear;
  let endMonth = req.query.endMonth;
  let endYear = req.query.endYear;
  let resultNum = req.query.resultNum;
  

  /* NIST CVE API URL  */
  const NIST_URL = "https://services.nvd.nist.gov/rest/json/cves/1.0";
  let nistTimeFrame = `?pubStartDate=${startYear}-${startMonth}-01T00:00:00:000 UTC-05:00`;
  let numResults = `&resultsPerPage=${startNum}`;

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
          let itemsarr = data.result.CVE_Items;
          console.log('how many things? ' + data.result.CVE_Items.length);
          console.log(plzwork);

          res.render('timeframe', { 
            title: 'Update',
            sometext: itemsarr, 
            title2: 'Check a file',
            //info: allDescriptions
           });
          
  })

  // error handling
  .catch(err => {
    if (err.response) {
      console.log("5xx/4xx error");
      console.log(err);
      res.render('error', {
        message: "an error occured"
      });
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
    title: "Find keyword regarding Vulnerabilities", 
    title2: "Check a file's hash",
    //info: allDescriptions
   });
});

router.get('/checkhash', function(req, res) {
  
  console.log(req.query);
  let md5hash = req.query.inputHash;
  
  let testHash1 = "10c027b28bfb9c569268746dd805fa7f";
  let testHash2 = "ffb456a28adf28a05af5746f996a96dc";
  let wannaCry1 = "db349b97c37d22f5ea1d1841e3c89eb4";

  /* VIRUS TOTAL API URL  */
  const VIRUS_TOTAL_URL = "https://www.virustotal.com/vtapi/v2/file/report";
  const vtKey = '?apikey=ed88a13aa2d037961fe2150650a49f970b766f3151e684ecbbfb22f04b3d50ca';
  let vtDomain = `&resource=${md5hash}`;

  axios
  .get(VIRUS_TOTAL_URL + vtKey + vtDomain)
  .then((response) => {
    console.log('vt api')

    // save the response to an object
    let { data } = response;
    console.log('attempt to display data');
    let display = JSON.stringify(data);
    //console.log(display);

    let symantecReport = data.scans.Symantec.result;
    //let esetnod32Report = ["data"]["scans"]["ESET-NOD32"]["result"]; // BRACKETS REQUIRED TO BYPASS -
    let bkavReport = data.scans.Bkav.result;

    // we are just interested in the CVE_Items array
    console.log(symantecReport);
    console.log("1");
    //console.log(esetnod32Report);
    console.log("2");
    console.log(bkavReport);
    console.log("3");
    // calculate how big the array is


    res.render('checkhash', { 
      hashSearched: md5hash,
      hashReport1: symantecReport,
      hashReport2: bkavReport
     });

  })

    // error handling
  .catch(err => {
    if (err.response) {
      console.log("5xx/4xx error");
      console.log(err);
      res.render('error', {
        message: "an error occured"
      });
    } else if (err.request) {
      console.log("something went wrong with response or request");
      console.log(err);
    }
    console.log(err);
    console.log("something went wrong, axios error");
  })
})

router.post('/', function (req, res) {
  console.log(req.body.selectDays);
  console.log(req.body.description);
  res.send('Post page');
});

module.exports = router;
