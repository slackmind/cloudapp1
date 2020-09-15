"use strict";
var express = require('express');
var router = express.Router();
const axios = require('axios').default;
const Joi = require('joi'); // input validation
const { TextAnalyticsClient, AzureKeyCredential } = require("@azure/ai-text-analytics");
const { PreconditionFailed } = require('http-errors');

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
    return;
  } 
  else {
    let keyword = holdInput.value.keyword;        //  assign using the sanitized input
    let resultNum = holdInput.value.resultNum;
    //let startMonth = ('0' + holdInput.value.startMonth).slice(-2); // add leading 0 if < 10
    //let startYear = holdInput.value.startYear;

    const NIST_URL = "https://services.nvd.nist.gov/rest/json/cves/1.0";
    let keywordSearch = `?keyword=${keyword}`;
    let numResults = `&resultsPerPage=${resultNum}`;
    try {
      const response = await axios.get(NIST_URL + keywordSearch + numResults)
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
        return;
      } 
      else if (err.request) {
        let errorMessage = "Something went wrong with response or request";
        res.render('error', {
          message: errorMessage,
          moretext: err
        });
        return;
      } 
      else {
      let errorMessage = "Axios error";
        res.render('error', {
          message: errorMessage,
          moretext: err
        });
        return;
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
        } 
        catch(err) {
          if (err.response) {
            let errorMessage = "5__ / 4__ error";
            res.render('error', {
              message: errorMessage,
              moretext: err
            });
            return;
          } 
          else if (err.request) {
            let errorMessage = "Something went wrong with response or request";
            res.render('error', {
              message: errorMessage,
              moretext: err
            });
            return;
          } 
          else {
          let errorMessage = "Axios error";
            res.render('error', {
              message: errorMessage,
              moretext: err
            });
            return;
        }
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
  });
});

router.get('/checkhash', async function (req, res) {

  console.log(req.query);
  // variables to store responses and use to query News
  let symantecReport;
  let sophosReport;
  let kasperskyReport;
  let microsoftReport;
  let trendMicroReport;
  let yandexReport;
  let cylanceReport;
  let reportArray = [];
  
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
    return;
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
    console.log("logging data scans " + data.scans);
    if (data.scans) {

      console.log("from symantec: ", data.scans.Symantec);
      // add best report summaries to array, with regex to clean 
      console.log("check data scans symantec " + data.scans.Symantec.detected);
      if (data.scans.Symantec.detected === true) {
        
        console.log("check result " + data.scans.Symantec.result);
        symantecReport = data.scans.Symantec.result
        .replace(/[`~!@#$%^&*()_|+\-=?;:'",.<>\{\}\[\]\\\/]/gi, ' ');
        console.log(symantecReport);
        reportArray.push(symantecReport);
      }
      if (data.scans.Sophos.detected === true) {
        sophosReport = data.scans.Sophos.result
        .replace(/[`~!@#$%^&*()_|+\-=?;:'",.<>\{\}\[\]\\\/]/gi, ' ');
        reportArray.push(sophosReport);
      }
      if (data.scans.Kaspersky.detected.length === true) {
        kasperskyReport = data.scans.Kaspersky.result
        .replace(/[`~!@#$%^&*()_|+\-=?;:'",.<>\{\}\[\]\\\/]/gi, ' ');
        reportArray.push(kasperskyReport);
      }
      if (data.scans.Microsoft.detected.length === true) {
        microsoftReport = data.scans.Microsoft.result
        .replace(/[`~!@#$%^&*()_|+\-=?;:'",.<>\{\}\[\]\\\/]/gi, ' ');
        console.log("microsoft" + microsoftReport);
        reportArray.push(microsoftReport);
      }
      if (data.scans.Yandex.detected.length === true) {
        yandexReport = data.scans.YandexMicro.result
        .replace(/[`~!@#$%^&*()_|+\-=?;:'",.<>\{\}\[\]\\\/]/gi, ' ');
        reportArray.push(yandexReport);
      }
      if (data.scans.Cylance.detected.length === true) {
        cylanceReport = data.scans.Cylance.result
        .replace(/[`~!@#$%^&*()_|+\-=?;:'",.<>\{\}\[\]\\\/]/gi, ' ');
        reportArray.push(cylanceReport);
      }
      if (data.scans.TrendMicro.detected === true) {
        trendMicroReport = data.scans.TrendMicro.result
        .replace(/[`~!@#$%^&*()_|+\-=?;:'",.<>\{\}\[\]\\\/]/gi, ' ');
        reportArray.push(trendMicroReport);
        console.log("trend micro" + trendMicroReport);
      }
  }
    
  }  
  catch(err) {
    if (err.response) {
      console.log("error1");
      let errorMessage = "5__ / 4__ error";
      res.render('error', {     // error page
        message: errorMessage,
        moretext: err
      });
      return;
    } 
    else if (err.request) {
      let errorMessage = "Something went wrong with response or request";
      res.render('error', {
        message: errorMessage,
        moretext: err
      });
      return;
    } 
    else {
      console.log("error3");
    let errorMessage = "Axios error";
      res.render('error', {
        message: errorMessage,
        moretext: err
      });
      return;
    }
  } 

  let searchNews = reportArray[0];
  console.log(searchNews);
  const NEWS_API_URL = "https://newsapi.org/v2/everything";
  const newsKey = "c61555335ae647768b810bcdeef93736";
  let newsQuery = `?q=${searchNews}&apiKey=${newsKey}`
  console.log()
  console.log("news api sent" + NEWS_API_URL + newsQuery);

  try {
    const response = await axios.get(NEWS_API_URL + newsQuery)

    let { data } = response;

    let newsArticles = data.totalResults;
    let newsSource = data.articles[0].source.name;
    let newsTitle = data.articles[0].title;
    let newsText = data.articles[0].description;
    console.log("queried news api");
    console.log("number of articles: " + newsArticles);
    console.log("from " + newsSource);
    console.log("Title: " + newsTitle);
    console.log(newsText);

    res.render('checkhash', {
      searchTopic: searchNews,
      numArticles: newsArticles,
      newsSource: newsSource,
      newsTitle: newsTitle,
      newsText: newsText,
    });
    
  }
  catch(err) {
    if (err.response) {
      let errorMessage = "5__ / 4__ error";
      res.render('error', {     // error page
        message: errorMessage,
        moretext: err
      });
      return;
    } else if (err.request) {
      let errorMessage = "Something went wrong with response or request";
      res.render('error', {
        message: errorMessage,
        moretext: err
      });
      return;
    } else {
      let errorMessage = "Axios error";
        res.render('error', {
          message: errorMessage,
          moretext: err
        });
        return;
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