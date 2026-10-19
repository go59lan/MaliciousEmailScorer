/**
 * Main entry point for the Add-on. Triggered when an email is opened.
 */
function buildAddOn(e) {
  // 1. Get the current email's data
  var accessToken = e.messageMetadata.accessToken;
  GmailApp.setCurrentMessageAccessToken(accessToken);
  var messageId = e.messageMetadata.messageId;
  var message = GmailApp.getMessageById(messageId);
  
  var attachments = message.getAttachments();
  var attachmentMeta = attachments.map(function(att) {
    var size = att.getSize();
    var base64Data = "";
    
    // Only send the file contents if it's under 5MB to prevent memory crashes
    if (size < 5 * 1024 * 1024) {
      base64Data = Utilities.base64Encode(att.getBytes());
    }
    
    return {
      name: att.getName(),
      size: size,
      base64_data: base64Data
    };
  });

  var payload = {
    sender: message.getFrom(),
    reply_to: message.getReplyTo(),
    subject: message.getSubject(),
    body: message.getBody(),
    attachments: attachmentMeta
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
 * Constructs the UI Card displaying the verdict, debrief, and findings.
 */
function buildResultCard(result) {
  var card = CardService.newCardBuilder();
  var section = CardService.newCardSection();
  
  // 1. Determine Color and Icon based on Verdict
  var iconUrl = "https://www.gstatic.com/images/icons/material/system/1x/check_circle_black_48dp.png"; // Default Safe
  var colorHex = "#2E7D32"; // Green
  
  if (result.verdict === "Critical") {
    iconUrl = "https://www.gstatic.com/images/icons/material/system/1x/error_black_48dp.png";
    colorHex = "#D32F2F"; // Red
  } else if (result.verdict === "High Risk" || result.verdict === "Suspicious") {
    iconUrl = "https://www.gstatic.com/images/icons/material/system/1x/warning_black_48dp.png";
    colorHex = "#ED6C02"; // Orange
  } else if (result.verdict === "Low Risk") {
    iconUrl = "https://www.gstatic.com/images/icons/material/system/1x/info_black_48dp.png";
    colorHex = "#0288D1"; // Blue
  }

  // 2. Verdict Header (Score removed)
  section.addWidget(CardService.newDecoratedText()
    .setTopLabel("THREAT ANALYSIS VERDICT")
    .setText("<font color='" + colorHex + "'><b>" + result.verdict + "</b></font>")
    .setStartIcon(CardService.newIconImage().setIconUrl(iconUrl)));
    
  card.addSection(section);
  
  // 3. NEW: Actionable Debrief Section
  var debriefSection = CardService.newCardSection()
    .setHeader("Recommended Action")
    .addWidget(CardService.newTextParagraph()
      .setText(result.debrief));
      
  card.addSection(debriefSection);

  // 4. Detailed Findings Section
  var findingsSection = CardService.newCardSection()
    .setHeader("Detailed Findings");
    
  if (result.reasons.length === 1 && result.reasons[0].indexOf("No suspicious") !== -1) {
     findingsSection.addWidget(CardService.newTextParagraph()
      .setText("<font color='#555555'><i>" + result.reasons[0] + "</i></font>"));
  } else {
    result.reasons.forEach(function(finding) {
      var findingIcon = "https://www.gstatic.com/images/icons/material/system/1x/chevron_right_black_48dp.png";
      
      if (finding.indexOf("Critical:") !== -1) findingIcon = "https://www.gstatic.com/images/icons/material/system/1x/cancel_black_48dp.png";
      else if (finding.indexOf("High:") !== -1) findingIcon = "https://www.gstatic.com/images/icons/material/system/1x/warning_amber_48dp.png";
      else if (finding.indexOf("Medium:") !== -1) findingIcon = "https://www.gstatic.com/images/icons/material/system/1x/help_outline_black_48dp.png";
      
      findingsSection.addWidget(CardService.newDecoratedText()
        .setText(finding)
        .setStartIcon(CardService.newIconImage().setIconUrl(findingIcon))
        .setWrapText(true)); 
    });
  }
    
  card.addSection(findingsSection);
  return card.build();
}