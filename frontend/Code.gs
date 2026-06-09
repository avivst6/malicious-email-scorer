function buildAddOn(e) {
  var messageId = e.gmail.messageId;
  var accessToken = e.gmail.accessToken;
  GmailApp.setCurrentMessageAccessToken(accessToken);

  var message = GmailApp.getMessageById(messageId);
  var sender = message.getFrom();
  var subject = message.getSubject();
  var bodySnippet = message.getPlainBody().substring(0, 100);

  var htmlBody = message.getBody();
  var links = [];
  var regex = /href="([^"]*)"/g;
  var match;
  while (match = regex.exec(htmlBody)) {
    links.push(match[1]);
  }

  var payload = {
    "sender": sender,
    "subject": subject,
    "bodySnippet": bodySnippet,
    "links": links
  };

  var serverUrl = "https://pampered-reclusive-ouch.ngrok-free.dev/analyze";

  var options = {
    "method": "post",
    "contentType": "application/json",
    "payload": JSON.stringify(payload),
    "muteHttpExceptions": true
  };

  var serverResponse;
  var score = "Error";
  var verdict = "Could not connect to server";
  var reason = "";

  try {
    serverResponse = UrlFetchApp.fetch(serverUrl, options);
    var result = JSON.parse(serverResponse.getContentText());
    score = result.score;
    verdict = result.verdict;
    reason = result.reason;
  } catch(error) {
    reason = error.toString();
  }

  var card = CardService.newCardBuilder();
  card.setHeader(CardService.newCardHeader().setTitle("Email Security Scan"));

  var section = CardService.newCardSection();
  section.addWidget(CardService.newTextParagraph().setText("<b>Score:</b> " + score + " / 10"));
  section.addWidget(CardService.newTextParagraph().setText("<b>Verdict:</b> " + verdict));
  section.addWidget(CardService.newTextParagraph().setText("<b>Reasons:</b> <br>" + reason));

  card.addSection(section);

  return card.build();
}
function forceAuth() {
  UrlFetchApp.fetch("https://www.google.com");
}