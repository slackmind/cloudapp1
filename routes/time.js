"use strict";
var express = require('express');
var router = express.Router();
const axios = require('axios').default;
const Joi = require('joi'); // input validation
const { TextAnalyticsClient, AzureKeyCredential } = require("@azure/ai-text-analytics");
const { PreconditionFailed } = require('http-errors');


router.get('/timeafter', async function (req, res) {
    let infoArray = [];
    let idCVEArray = [];
    
    const schema = Joi.object({   // define validation schema
    startMonth: Joi.number().min(1).max(12).positive().integer().required(),
    startYear: Joi.number().min(2006).max(2020).positive().integer().required(),
    resultNum: Joi.number().min(1).max(10).positive().integer().required(),
    });
  
  
  let holdInput = schema.validate(req.query);   // validate the request data against the schema
  
  
  if (holdInput.error) {    // check if anything went wrong
    let errorMessage = holdInput.error.details[0].message;
    let message2 = "Please check your input and try again";
    res.render('error', {       // error page
      message: errorMessage,
      msg2: message2
    });
    return;
  } 
  else {
    // assign values
    let startMonth = ('0' + holdInput.value.startMonth).slice(-2); // add leading 0 if < 10
    let startYear = holdInput.value.startYear;
    let resultNum = holdInput.value.resultNum;
    
    const NIST_URL = "https://services.nvd.nist.gov/rest/json/cves/1.0";
    let startTime = `?modStartDate=${startYear}-${startMonth}-01T00:00:00:000%20UTC-05:00`;
    let numResults = `&resultsPerPage=${resultNum}`;
    //let testt = "https://services.nvd.nist.gov/rest/json/cves/1.0?modStartDate=2019-01-01T00:00:00:000%20UTC-05:00";
    
    try {
      const response = await axios.get(NIST_URL + startTime + numResults)
  
      let { data } = response
      let infoArraySize = data.result.CVE_Items.length;
  
      if (infoArraySize > 0) {
        let i;
        for (i = 0; i < infoArraySize; i++) {
          let tempObj1 = {}      // define intermediate objects within loop
          let tempObj2 = {}
          tempObj1 = data.result.CVE_Items[i].cve.description.description_data[0].value;
          infoArray.push(tempObj1);
          tempObj2 = data.result.CVE_Items[i].cve.CVE_data_meta.ID;
          idCVEArray.push(tempObj2);
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
  
    const textAnalyticsClient = new TextAnalyticsClient(  //  create new client with my endpoint and API key
                                  azureEndPoint,  
                                  new AzureKeyCredential(azureKey));
    
    async function keyPhraseExtraction(client){
        const keyPhraseResult = await client.extractKeyPhrases(infoArray);
        res.render('timeframe', {
          beforeOrAfter: "After",
          month: startMonth,
          year: startYear,
          cveIDs: idCVEArray,
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
  
  router.get('/timebefore', async function (req, res) {
    let infoArray = [];
    let idCVEArray = [];
    
    const schema = Joi.object({   // define validation schema
    endMonth: Joi.number().min(1).max(12).positive().integer(),
    endYear: Joi.number().min(2006).max(2020).positive().integer(),
    resultNum: Joi.number().min(1).max(10).positive().integer().required(),
    });
  
  
  let holdInput = schema.validate(req.query);   // validate the request data against the schema
  
  
  if (holdInput.error) {    // check if anything went wrong
    let errorMessage = holdInput.error.details[0].message;
    let message2 = "Please check your input and try again";
    res.render('error', {       // error page
      message: errorMessage,
      msg2: message2
    });
    return;
  } 
  else {
    // assign values
    let endMonth = ('0' + holdInput.value.endMonth).slice(-2);
    let endYear = holdInput.value.endYear;
    let resultNum = holdInput.value.resultNum;
    
    const NIST_URL = "https://services.nvd.nist.gov/rest/json/cves/1.0";
    let endTime = `?modEndDate=${endYear}-${endMonth}-01T00:00:00:000%20UTC-05:00`;
    let numResults = `&resultsPerPage=${resultNum}`;
    //let testt = "https://services.nvd.nist.gov/rest/json/cves/1.0?modStartDate=2019-01-01T00:00:00:000%20UTC-05:00";
    
    try {
      const response = await axios.get(NIST_URL + endTime + numResults)
  
      let { data } = response
      let infoArraySize = data.result.CVE_Items.length;
  
      if (infoArraySize > 0) {
        let i;
        for (i = 0; i < infoArraySize; i++) {
          let tempObj1 = {}      // define intermediate objects within loop
          let tempObj2 = {}
          tempObj1 = data.result.CVE_Items[i].cve.description.description_data[0].value;
          infoArray.push(tempObj1);
          tempObj2 = data.result.CVE_Items[i].cve.CVE_data_meta.ID;
          idCVEArray.push(tempObj2);
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
    //const azureKey = "c8c62ec3e50a43faaf1df63ffbad697c";
    const azureKey = process.env.MSFKEY;
    const textAnalyticsClient = new TextAnalyticsClient(  //  create new client with my endpoint and API key
                                  azureEndPoint,  
                                  new AzureKeyCredential(azureKey));
    
    async function keyPhraseExtraction(client){
        const keyPhraseResult = await client.extractKeyPhrases(infoArray);
        res.render('timeframe', {
          beforeOrAfter: "Before",
          month: endMonth,
          year: endYear,
          cveIDs: idCVEArray,
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

  module.exports = router;