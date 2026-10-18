/**
 * Main entry point for the Add-on. Triggered when an email is opened.
 */
function buildAddOn(e) {
  // 1. Get the current email's data
  var accessToken = e.messageMetadata.accessToken;
  GmailApp.setCurrentMessageAccessToken(accessToken);
  var messageId = e.messageMetadata.messageId;
  var message = GmailApp.getMessageById(messageId);
  
  var payload = {
    sender: message.getFrom(),
    subject: message.getSubject(),
    body: message.getPlainBody() // Using plain body to avoid sending raw HTML for now
  };
  
  // 2. Send data to your Python backend
  // NOTE: Replace this URL with your active ngrok URL
  var backendUrl = "https://playgroup-uplifting-undoing.ngrok-free.dev/analyze";
  
  var options = {
    method: "post",
    contentType: "application/json",
    payload: JSON.stringify(payload),
    muteHttpExceptions: true,
    headers: {
      "ngrok-skip-browser-warning": "true"
    }
  };
  
  var response;
  var result;
  
  var response;
  var result;
  
  try {
    response = UrlFetchApp.fetch(backendUrl, options);
    var responseCode = response.getResponseCode();
    var rawContent = response.getContentText();
    
    // If it's not a success code, show exactly what the server returned
    if (responseCode !== 200) {
      return buildErrorCard("HTTP Error " + responseCode + ": \n" + rawContent.substring(0, 150));
    }
    
    result = JSON.parse(rawContent);
  } catch (error) {
    // This catches code errors, like JSON parsing failures
    return buildErrorCard("Script Error: " + error.toString());
  }

  // 3. Build the UI Card with the results
  return buildResultCard(result);
  }

/**
 * Constructs the UI Card displaying the score and verdict.
 */
function buildResultCard(result) {
  var card = CardService.newCardBuilder()
    .setHeader(CardService.newCardHeader().setTitle("Analysis Results"));
    
  var section = CardService.newCardSection();
  
  // Display Score
  section.addWidget(CardService.newDecoratedText()
    .setTopLabel("Risk Score")
    .setText(result.score.toString() + " / 100"));
    
  // Display Verdict
  section.addWidget(CardService.newDecoratedText()
    .setTopLabel("Verdict")
    .setText("<b>" + result.verdict + "</b>"));
    
  // Display Reasons
  var reasonsText = result.reasons.length > 0 ? result.reasons.map(function(r) { return "- " + r; }).join("<br>") : "No suspicious indicators found.";
  
  section.addWidget(CardService.newTextParagraph()
    .setText("<b>Reasoning:</b><br>" + reasonsText));
    
  card.addSection(section);
  return card.build();
}

/**
 * Fallback card if the backend is unreachable.
 */
function buildErrorCard(errorMessage) {
  var card = CardService.newCardBuilder();
  var section = CardService.newCardSection()
    .addWidget(CardService.newTextParagraph().setText(errorMessage));
  card.addSection(section);
  return card.build();
}