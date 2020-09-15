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
    keyword: Joi.string().alphanum().min(3).max(20).required(),
    resultNum: Joi.number().min(1).max(10).positive().integer().required(),
    startMonth: Joi.number().min(1).max(12).positive().integer().required(),
    startYear: Joi.number().min(1995).max(2020).positive().integer().required(),
  });

  let holdInput = schema.validate(req.query); // validate the request data using schema
  
  if (holdInput.error) {      // check if anything went wrong
    let errorMessage = holdInput.error.details[0].message;
    console.log("errorrrr");

    res.render('error', {     // error page
      message: errorMessage,
    });
  } 
  
  else {

    let keyword = holdInput.value.keyword;        //  assign using the sanitized input
    let resultNum = holdInput.value.resultNum;
    let startMonth = ('0' + holdInput.value.startMonth).slice(-2); // add leading 0 if < 10
    let startYear = holdInput.value.startYear;
    console.log(startYear);
    console.log(startMonth);

    const NIST_URL = "https://services.nvd.nist.gov/rest/json/cves/1.0";
    let keywordSearch = `?keyword=${keyword}`;
    let numResults = `&resultsPerPage=${resultNum}`;
    let timeFrame = `?modStartDate=${startYear}-${startMonth}-01T00:00:00:000 UTC-05:00`;

    try {
      const response = await axios.get(NIST_URL + timeFrame + keywordSearch + numResults)
      console.log("query url with all the things");
      let { data } = response;
      let infoArraySize = data.result.CVE_Items.length;
      console.log(infoArraySize);
  
      if (infoArraySize > 0) {    // check we got anything back
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
                                azureEndPoint,    
                                new AzureKeyCredential(azureKey));
    
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

router.get('/checkhash', async function (req, res) {

  // variables to store responses and use to query News
  let symantecReport;
  let sophosReport;
  let kasperskyReport;
  let alibabaReport;
  let trendmicroReport;

  console.log(req.query);

  
  const schema = Joi.object({       // validation (md5,sha1, sha256 are 32-64 hex characters)
  inputHash: Joi.string().min(32).max(64).hex().required()
  });

  
  let holdInput = schema.validate(req.query);   // validate the request data against the schema
  console.log("the input is  " + JSON.stringify(holdInput));
  
  if (holdInput.error) {    // check if anything went wrong
    let errorMessage = holdInput.error.details[0].message;
    console.log("error is " + errorMessage);
    
    res.render('error', {   // error page
      message: errorMessage,
    });
  } 

else {

  let fileHash = holdInput.value.inputHash;

  // from https://virusshare.com/hashfiles/VirusShare_00000.md5 and 
  // from https://www.fireeye.com/blog/threat-research/2017/05/wannacry-malware-profile.html
  // other ideas https://www.cisecurity.org/blog/top-10-malware-january-2019/
  let testHash1 = "10c027b28bfb9c569268746dd805fa7f";
  let testHash2 = "ffb456a28adf28a05af5746f996a96dc";
  let wannaCry1 = "db349b97c37d22f5ea1d1841e3c89eb4";

  /* VIRUS TOTAL API URL  */
  //const VIRUS_TOTAL_URL = process.env.VT_KEY
  const loadVTKey = process.env.virusTotalKey;
  const VIRUS_TOTAL_URL = "https://www.virustotal.com/vtapi/v2/file/report";
  const VIRUS_TOTAL_KEY = "ed88a13aa2d037961fe2150650a49f970b766f3151e684ecbbfb22f04b3d50ca";
  const vtKey = `?apikey=${VIRUS_TOTAL_KEY}`;
  let vtDomain = `&resource=${fileHash}`;


  
  try {
    const response = await axios.get(VIRUS_TOTAL_URL + vtKey + vtDomain)

    let { data } = response;

    console.log("logging data.scans" + data.scans);
    if ( data.scans ) {

      // best report summaries with regex to clean
      symantecReport = data.scans.Symantec.result
      .replace(/[`~!@#$%^&*()_|+\-=?;:'",.<>\{\}\[\]\\\/]/gi, ' ');
      sophosReport = data.scans.Sophos.result
      .replace(/[`~!@#$%^&*()_|+\-=?;:'",.<>\{\}\[\]\\\/]/gi, ' ');
      kasperskyReport = data.scans.Kaspersky.result
      .replace(/[`~!@#$%^&*()_|+\-=?;:'",.<>\{\}\[\]\\\/]/gi, ' ');
      alibabaReport = data.scans.Alibaba.result
      .replace(/[`~!@#$%^&*()_|+\-=?;:'",.<>\{\}\[\]\\\/]/gi, ' ');
      trendmicroReport = data.scans.TrendMicro.result
      .replace(/[`~!@#$%^&*()_|+\-=?;:'",.<>\{\}\[\]\\\/]/gi, ' ');
  }
    
  }  catch(err) {
    if (err.response) {
      console.log("error1");
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
      console.log("error3");
    let errorMessage = "Axios error";
      res.render('error', {
        message: errorMessage,
        moretext: err
      });
    }
  }

  const NEWS_API_URL = "https://newsapi.org/v2/everything";
  const newsKey = "c61555335ae647768b810bcdeef93736";
  let newsQuery = `?q=${symantecReport}&apiKey=${newsKey}`
  console.log(NEWS_API_URL + newsQuery);

  try {
    const response = await axios.get(NEWS_API_URL + newsQuery)

    let { data } = response;

    let newsArticles = data.totalResults;
    if (newsArticles === 0) {
      console.log("no news!");
    }
    let newsSource = data.articles[0].source.name;
    let newsTitle = data.articles[0].title;
    let newsText = data.articles[0].description;
    console.log("queried news api");
    console.log("number of articles: " + newsArticles);
    console.log("from " + newsSource);
    console.log("Title: " + newsTitle);
    console.log(newsText);

    res.render('checkhash', {
      hashSearched: fileHash,
      hashReport1: symantecReport,
      hashReport2: sophosReport,
      hashReport3: kasperskyReport,
      hashReport4: alibabaReport,
      hashReport5: trendmicroReport,
      newsReport: newsText
    });
  }
  catch(err) {
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
  
}
  
});

router.post('/', function (req, res) {
  console.log(req.body.selectDays);
  console.log(req.body.description);
  res.send('Post page');
});

module.exports = router;