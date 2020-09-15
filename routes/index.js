"use strict";
var express = require('express');
var router = express.Router();
const axios = require('axios').default;
const Joi = require('joi'); // input validation
// Imports the Google Cloud client library
const language = require('@google-cloud/language');
const { TextAnalyticsClient, AzureKeyCredential } = require("@azure/ai-text-analytics");

router.get('/searchterm', async function (req, res) {

  let infoArray = [];             // store the first response from the API
  
  const schema = Joi.object({     // define validation schema
    keyword: Joi.string().alphanum().min(3).max(16).required(),
    resultNum: Joi.number().min(1).max(20).positive().integer().required(),
  });

  let holdInput = schema.validate(req.query); // validate the request data using schema
  console.log("the input is  " + JSON.stringify(holdInput));
  
  if (holdInput.error) {      // check if anything went wrong
    let errorMessage = holdInput.error.details[0].message;
    console.log("error is " + errorMessage);
    // error page
    res.render('error', {
      message: errorMessage,
    });
  } else {

    let keyword = holdInput.value.keyword;        //  assign using the sanitized input
    let resultNum = holdInput.value.resultNum;
    
    const NIST_URL = "https://services.nvd.nist.gov/rest/json/cves/1.0";
    let keywordSearch = `?keyword=${keyword}`;
    let numResults = `&resultsPerPage=${resultNum}`;

    try {
      const response = await axios.get(NIST_URL + keywordSearch + numResults)

      let { data } = response
      let infoArraySize = data.result.CVE_Items.length;
  
      if (infoArraySize > 0) {
        let i;
        for (i = 0; i < infoArraySize; i++) {
          let tempObj = {}      // define intermediate object within loop
          tempObj = data.result.CVE_Items[i].cve.description.description_data[0].value;
          infoArray.push(tempObj);
          console.log("iterating");
        }
      }
    }  catch(err) {
      if (err.response) {
        let errorMessage = "5__ / 4__ error";
        res.render('error', {     // error page
          message: errorMessage,
          moretext: err
        });
      } else if (err.request) {
        let errorMessage = "Something went wrong with response or request";
        res.render('error', {
          message: errorMessage,
          moretext: err
        });
      } else {
      let errorMessage = "Axios error";
        res.render('error', {
          message: errorMessage,
          moretext: err
        });
      }
    }

    // Azure Language Processing API
    const azureEndPoint = "https://textcreate.cognitiveservices.azure.com/";
    const azureKey = "c8c62ec3e50a43faaf1df63ffbad697c";

    //  create new client with my endpoint and API key
    const textAnalyticsClient = new TextAnalyticsClient(
      azureEndPoint,  new AzureKeyCredential(azureKey));
    
    /* from https://docs.microsoft.com/en-us/azure/cognitive-services
    /text-analytics/quickstarts/text-analytics-sdk?pivots=programming-
    language-javascript&tabs=version-3#client-authentication */
    async function keyPhraseExtraction(client){
        
        const keyPhraseResult = await client.extractKeyPhrases(infoArray);
        
        keyPhraseResult.forEach(document => {
            //console.log(`ID: ${document.id}`);
            //console.log(`\tDocument Key Phrases: ${document.keyPhrases}`);
        });
        console.log(keyword);
        console.log(keyPhraseResult[0].keyPhrases);
        res.render('searchterm', {
          searchedFor: keyword,
          sometext: keyPhraseResult,
         
        });
    }
        
        try {
          await keyPhraseExtraction(textAnalyticsClient);
        } catch(err) {
          if (err.response) {
            let errorMessage = "5__ / 4__ error";
            res.render('error', {
              message: errorMessage,
              moretext: err
            });
          } else if (err.request) {
            let errorMessage = "Something went wrong with response or request";
            res.render('error', {
              message: errorMessage,
              moretext: err
            });
          }
          let errorMessage = "Axios error";
            res.render('error', {
              message: errorMessage,
              moretext: err
            });
        }
   }
});

router.get('/timeframe', function (req, res) {

  console.log(req.query);

  // define validation schema
  const schema = Joi.object({
  startMonth: Joi.number().min(1).max(12).positive().integer().required(),
  startYear: Joi.number().min(1995).max(2020).positive().integer().required(),
  endMonth: Joi.number().min(1).max(12).positive().integer(),
  endYear: Joi.number().min(Joi.ref('startYear')).max(2020).positive().integer(),
  resultNum: Joi.number().min(1).max(10).positive().integer(),
  });

// validate the request data against the schema
let holdInput = schema.validate(req.query);
console.log("the input is  " + JSON.stringify(holdInput));

// check if anything went wrong
if (holdInput.error) {
  let errorMessage = holdInput.error.details[0].message;
  console.log("error is " + errorMessage);
  // error page
  res.render('error', {
    message: errorMessage,
  });
} else {
  console.log("ok without error");
  // assign values
  let startMonth = ('0' + holdInput.value.startMonth).slice(-2);
  let startYear = holdInput.value.startYear;
  let endMonth = holdInput.value.endMonth;
  let endYear = holdInput.value.endYear;
  let resultNum = holdInput.value.resultNum;

  console.log(startMonth);
  startMonth = ('0' + startMonth).slice(-2);
  console.log(startMonth);

  
  /* NIST CVE API URL  */
  const NIST_URL = "https://services.nvd.nist.gov/rest/json/cves/1.0";
  let startTime = `?modStartDate=${startYear}-${startMonth}-01T00:00:00:000%20UTC-05:00`;
  let endTime = `?modStartDate=${endYear}-${endMonth}-01T00:00:00:000%20UTC-05:00`;
  let numResults = `&resultsPerPage=${resultNum}`;
  let testt = "https://services.nvd.nist.gov/rest/json/cves/1.0?modStartDate=2019-01-01T00:00:00:000%20UTC-05:00";
  console.log("maybe not");
  axios
    .get(NIST_URL + startTime + numResults)

    .then((response) => {
      console.log('got here')

      // save the response to an object
      let {
        data
      } = response;
      console.log('attempt to display data');

      let infoArray = [];
        let infoArraySize = data.result.CVE_Items.length;
    
        if (infoArraySize > 0) {
          let i;
          for (i = 0; i < infoArraySize; i++) {
            let tempObj = {}
            tempObj = data.result.CVE_Items[i].cve.description.description_data[0].value;
            infoArray.push(tempObj);
            console.log("iterating");
            //console.log(infoArray[i]);
          }
        }


      res.render('timeframe', {
        title: 'Update',
        sometext: infoArray,
        title2: 'Check a file',
        //info: allDescriptions
      });

    }).catch(err => {
      if (err.response) {
        let errorMessage = "5__ / 4__ error";

        res.render('error', {
          message: errorMessage,
          moretext: err
        });
        
      } else if (err.request) {
        let errorMessage = "Something went wrong with response or request";

        res.render('error', {
          message: errorMessage,
          moretext: err
        });
      } else {
      let errorMessage = "Axios error";

        res.render('error', {
          message: errorMessage,
          moretext: err
        });
      }
    })

    // end of error
  }
});

/* GET home page. */
router.get('/', function (req, res) {

  let firstPart = "Summarise vulnerability reports";
  let secondPart = "Find articles regarding malicious files";

  res.render('index', {
    title: firstPart,
    title2: secondPart,
    //info: allDescriptions
  });
});

router.get('/checkhash', function (req, res) {

  console.log(req.query);

  // define validation schema
const schema = Joi.object({
  inputHash: Joi.string().alphanum().min(32).max(64).required()
});

// validate the request data against the schema
let holdInput = schema.validate(req.query);
console.log("the input is  " + JSON.stringify(holdInput));
// check if anything went wrong
if (holdInput.error) {
  let errorMessage = holdInput.error.details[0].message;
  console.log("error is " + errorMessage);
  // error page
  res.render('error', {
    message: errorMessage,
  });
} else {
  let md5hash = holdInput.value.inputHash;

  // from https://virusshare.com/hashfiles/VirusShare_00000.md5 and 
  // from https://www.fireeye.com/blog/threat-research/2017/05/wannacry-malware-profile.html
  // other ideas https://www.cisecurity.org/blog/top-10-malware-january-2019/
  let testHash1 = "10c027b28bfb9c569268746dd805fa7f";
  let testHash2 = "ffb456a28adf28a05af5746f996a96dc";
  let wannaCry1 = "db349b97c37d22f5ea1d1841e3c89eb4";

  /* VIRUS TOTAL API URL  */
  //const VIRUS_TOTAL_URL = process.env.VT_KEY
  const VIRUS_TOTAL_URL = "https://www.virustotal.com/vtapi/v2/file/report";
  const VIRUS_TOTAL_KEY = "ed88a13aa2d037961fe2150650a49f970b766f3151e684ecbbfb22f04b3d50ca";
  const vtKey = `?apikey=${VIRUS_TOTAL_KEY}`;
  let vtDomain = `&resource=${md5hash}`;

  axios
    .get(VIRUS_TOTAL_URL + vtKey + vtDomain)
    .then((response) => {
      console.log('vt api')

      // save the response to an object
      let {
        data
      } = response;

      // best report summaries
      let symantecReport = data.scans.Symantec.result
      .replace(/[`~!@#$%^&*()_|+\-=?;:'",.<>\{\}\[\]\\\/]/gi, ' ');
      let sophosReport = data.scans.Sophos.result
      .replace(/[`~!@#$%^&*()_|+\-=?;:'",.<>\{\}\[\]\\\/]/gi, ' ');
      let kasperskyReport = data.scans.Kaspersky.result
      .replace(/[`~!@#$%^&*()_|+\-=?;:'",.<>\{\}\[\]\\\/]/gi, ' ');
      let alibabaReport = data.scans.Alibaba.result
      .replace(/[`~!@#$%^&*()_|+\-=?;:'",.<>\{\}\[\]\\\/]/gi, ' ');
      let trendmicroReport = data.scans.TrendMicro.result
      .replace(/[`~!@#$%^&*()_|+\-=?;:'",.<>\{\}\[\]\\\/]/gi, ' ');

      // news api key
      let dummySearch = "apple";
      const NEWS_API_URL = "https://newsapi.org/v2/everything";
      const newsKey = "c61555335ae647768b810bcdeef93736";
      let newsQuery = `?q=${dummySearch}&apiKey=${newsKey}`
      console.log(NEWS_API_URL + newsQuery);



      axios
        .get(NEWS_API_URL + newsQuery)
        .then((response) => {

          console.log("ok we made it");
          console.log(response);
          let {
            data2
          } = response;
          console.log(data2);
          let textdata2 = JSON.stringify(data2);
          console.log(textdata2);
        })

        



      res.render('checkhash', {
        hashSearched: md5hash,
        hashReport1: symantecReport,
        hashReport2: sophosReport,
        hashReport3: kasperskyReport,
        hashReport4: alibabaReport,
        hashReport5: trendmicroReport,
        /*newsReport: okNowNews */
      });

    })

    // error handling
    .catch(err => {
      if (err.response) {
        //console.log("5xx/4xx error");
        //console.log(err);
        res.render('error', {
          message: "an error occured"
        });
      } else if (err.request) {
        //console.log("something went wrong with response or request");
        //console.log(err);
      } else {
      //console.log(err);
      console.log("something went wrong, axios error");
    }
  })
}
  
});

router.post('/', function (req, res) {
  console.log(req.body.selectDays);
  console.log(req.body.description);
  res.send('Post page');
});

module.exports = router;