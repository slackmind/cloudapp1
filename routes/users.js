"use strict";
var express = require('express');
var router = express.Router();
const axios = require('axios').default;
const Joi = require('joi'); // input validation
const { TextAnalyticsClient, AzureKeyCredential } = require("@azure/ai-text-analytics");
const { PreconditionFailed } = require('http-errors');
/*
router.get('/timeframe', async function (req, res) {

  let infoArray = [];

  // define validation schema
  const schema = Joi.object({
  startMonth: Joi.number().min(1).max(12).positive().integer().required(),
  startYear: Joi.number().min(1995).max(2020).positive().integer().required(),
  endMonth: Joi.number().min(1).max(12).positive().integer(),
  endYear: Joi.number().min(Joi.ref('startYear')).max(2020).positive().integer(),
  resultNum: Joi.number().min(1).max(10).positive().integer().required(),
  });

// validate the request data against the schema
let holdInput = schema.validate(req.query);

// check if anything went wrong
if (holdInput.error) {
  let errorMessage = holdInput.error.details[0].message;
  console.log("error is " + errorMessage);
  // error page
  res.render('error', {
    message: errorMessage,
  });
  return;
} 

else {
  console.log("ok without error");
  // assign values
  let startMonth = ('0' + holdInput.value.startMonth).slice(-2); // add leading 0 if < 10
  let startYear = holdInput.value.startYear;
  let endMonth = ('0' + holdInput.value.endMonth).slice(-2);
  let endYear = holdInput.value.endYear;
  let resultNum = holdInput.value.resultNum;

  
  const NIST_URL = "https://services.nvd.nist.gov/rest/json/cves/1.0";
  let startTime = `?modStartDate=${startYear}-${startMonth}-01T00:00:00:000%20UTC-05:00`;
  let endTime = `?modStartDate=${endYear}-${endMonth}-01T00:00:00:000%20UTC-05:00`;
  let numResults = `&resultsPerPage=${resultNum}`;
  //let testt = "https://services.nvd.nist.gov/rest/json/cves/1.0?modStartDate=2019-01-01T00:00:00:000%20UTC-05:00";
  console.log("maybe not");
  
  
  try {
    const response = await axios.get(NIST_URL + startTime + numResults)

    let { data } = response
    let infoArraySize = data.result.CVE_Items.length;
    console.log("info array" + infoArraySize);

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
    }
  }

  // Azure Language Processing API
  const azureEndPoint = "https://textcreate.cognitiveservices.azure.com/";
  const azureKey = "c8c62ec3e50a43faaf1df63ffbad697c";

  //  create new client with my endpoint and API key
  const textAnalyticsClient = new TextAnalyticsClient(
                                azureEndPoint,  
                                new AzureKeyCredential(azureKey));
  
  async function keyPhraseExtraction(client){
      
      const keyPhraseResult = await client.extractKeyPhrases(infoArray);
      
      //keyPhraseResult.forEach(document => {
          //console.log(`ID: ${document.id}`);
          //console.log(`\tDocument Key Phrases: ${document.keyPhrases}`);
      //});
      console.log(keyword);
      console.log(keyPhraseResult[0].keyPhrases);

      res.render('timeframe', {
        startMonth: startMonth,
        startYear: startYear,
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

module.exports = router; */
