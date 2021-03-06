"use strict";
var express = require('express');
var router = express.Router();
const axios = require('axios').default;
const Joi = require('joi'); // input validation
const { TextAnalyticsClient, AzureKeyCredential } = require("@azure/ai-text-analytics");
const { PreconditionFailed } = require('http-errors');

/* GET home page. */
router.get('/', function (req, res) {

  let firstPart = "Summarise vulnerability reports";
  let secondPart = "Find articles regarding malicious files";

  res.render('index', {
    title: firstPart,
    title2: secondPart,
  });
});


router.get('/searchterm', async function (req, res) {

  let infoArray = []; // store the first response from the API
  let idCVEArray = [];

  const schema = Joi.object({ // define validation schema
    keyword: Joi.string().alphanum().min(3).max(20).required(),
    resultNum: Joi.number().min(1).max(10).positive().integer().required(),
  });

  let holdInput = schema.validate(req.query); // validate the request data using schema

  if (holdInput.error) { // check if anything went wrong
    let errorMessage = holdInput.error.details[0].message;
    let message2 = "Please check your input and try again";
    res.render('error', { // error page
      message: errorMessage,
      msg2: message2
    });
    return;
  } else {
    let keyword = holdInput.value.keyword; //  assign using the sanitized input
    let resultNum = holdInput.value.resultNum;

    const NIST_URL = "https://services.nvd.nist.gov/rest/json/cves/1.0";
    let keywordSearch = `?keyword=${keyword}`;
    let numResults = `&resultsPerPage=${resultNum}`;
    try {
      const response = await axios.get(NIST_URL + keywordSearch + numResults)
      let {
        data
      } = response;
      let infoArraySize = data.result.CVE_Items.length;

      if (infoArraySize > 0) { // check we got anything back
        let i;
        for (i = 0; i < infoArraySize; i++) {
          let tempObj1 = {} // define intermediate objects within loop
          let tempObj2 = {}
          tempObj1 = data.result.CVE_Items[i].cve.description.description_data[0].value;
          infoArray.push(tempObj1);
          tempObj2 = data.result.CVE_Items[i].cve.CVE_data_meta.ID;
          idCVEArray.push(tempObj2);
        }
      }
    } catch (err) {
      if (err.response) {
        let errorMessage = "5__ / 4__ error";
        res.render('error', { // error page
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

    // Azure Language Processing API
    const azureEndPoint = "https://textcreate.cognitiveservices.azure.com/";
    //const azureKey = "c8c62ec3e50a43faaf1df63ffbad697c";
    const azureKey = process.env.MSFKEY

    //  create new client with my endpoint and API key
    const textAnalyticsClient = new TextAnalyticsClient(
      azureEndPoint,
      new AzureKeyCredential(azureKey));

    /* taken from https://docs.microsoft.com/en-us/azure/cognitive-services/
    text-analytics/quickstarts/text-analytics-sdk?pivots=programming-
    language-javascript&tabs=version-3#client-authentication */
    async function keyPhraseExtraction(client) {

      const keyPhraseResult = await client.extractKeyPhrases(infoArray);
      res.render('searchterm', {
        cveIDs: idCVEArray,
        searchedFor: keyword,
        sometext: keyPhraseResult,
      });
    }
    try {
      await keyPhraseExtraction(textAnalyticsClient);
    } catch (err) {
      if (err.response) {
        let errorMessage = "5__ / 4__ error";
        res.render('error', {
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

router.get('/checkhash', async function (req, res) {

  // variables to store responses and use to query News
  // the most reputable companies (hopefully)
  let symantecReport;
  let sophosReport;
  let kasperskyReport;
  let microsoftReport;
  let trendMicroReport;
  let yandexReport;
  let cylanceReport;
  let searchNews;
  let reportArray = [];
  let articleArray = [];

  const schema = Joi.object({ // validation (md5,sha1, sha256 are 32-64 hex characters)
    inputHash: Joi.string().min(32).max(64).hex().required()
  });

  let holdInput = schema.validate(req.query); // validate the request data against the schema

  if (holdInput.error) { // check if anything went wrong
    let errorMessage = holdInput.error.details[0].message;
    let message2 = "Please check your input and try again";
    res.render('error', { // error page
      message: errorMessage,
      msg2: message2
    });
    return;
  } else {
    let fileHash = holdInput.value.inputHash;



    const VIRUS_TOTAL_URL = "https://www.virustotal.com/vtapi/v2/file/report";
    const VIRUS_TOTAL_KEY = process.env.VTKEY
    const vtKey = `?apikey=${VIRUS_TOTAL_KEY}`;
    let vtDomain = `&resource=${fileHash}`;

    try {
      const response = await axios.get(VIRUS_TOTAL_URL + vtKey + vtDomain)

      let {
        data
      } = response;
      if (data.scans) { // see if we got any reports

        // add best report summaries to array, with regex to clean 
        if (data.scans.Symantec.detected === true) {
          symantecReport = data.scans.Symantec.result
            .replace(/[`~!@#$%^&*()_|+\-=?;:'",.<>\{\}\[\]\\\/]/gi, ' ');
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
        }
      }

    } catch (err) {
      if (err.response) {
        let errorMessage = "5__ / 4__ error";
        res.render('error', { // error page
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

    searchNews = reportArray[0];
    const NEWS_API_URL = "https://newsapi.org/v2/everything";
    const newsKey = process.env.NEWSKEY;
    let newsQuery = `?q=${searchNews}&apiKey=${newsKey}`

    try {
      const response = await axios.get(NEWS_API_URL + newsQuery)

      let {
        data
      } = response;

      let numArticles = data.totalResults;
      if (numArticles) {
        let i;
        for (i = 0; i < numArticles && i < 10; i++) {
          let tempObj = {} // define intermediate object within loop
          tempObj = data.articles[i];
          articleArray.push(tempObj);
        }
      }
      res.render('checkhash', {
        searchTopic: searchNews,
        allArticles: articleArray,
        numArticles: numArticles,
      });

    } catch (err) {
      if (err.response) {
        let errorMessage = "5__ / 4__ error";
        res.render('error', { // error page
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

module.exports = router;