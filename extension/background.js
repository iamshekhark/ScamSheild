// ScamShield Background Service Worker (Manifest V3)
importScripts("rules.js");

chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({
    id: "scamshield-scan-selection",
    title: "🛡️ ScamShield: Check selected text",
    contexts: ["selection"]
  });

  chrome.contextMenus.create({
    id: "scamshield-scan-link",
    title: "🛡️ ScamShield: Check this link",
    contexts: ["link"]
  });

  chrome.contextMenus.create({
    id: "scamshield-scan-page",
    title: "🛡️ ScamShield: Check this page URL",
    contexts: ["page"]
  });
});

chrome.contextMenus.onClicked.addListener(async (info, tab) => {
  let result = null;
  let inputType = "text";
  let content = "";

  if (info.menuItemId === "scamshield-scan-selection" && info.selectionText) {
    inputType = "text";
    content = info.selectionText;
    result = ScamEngine.scanText(content);
  } else if (info.menuItemId === "scamshield-scan-link" && info.linkUrl) {
    inputType = "url";
    content = info.linkUrl;
    result = ScamEngine.scanUrl(content);
  } else if (info.menuItemId === "scamshield-scan-page" && tab?.url) {
    inputType = "url";
    content = tab.url;
    result = ScamEngine.scanUrl(content);
  }

  if (result) {
    // Save to storage so popup opens with this result
    await chrome.storage.local.set({
      lastScan: {
        ...result,
        input_type: inputType,
        content_preview: content.slice(0, 200),
        timestamp: new Date().toLocaleTimeString()
      }
    });

    // Update badge color & text
    const badgeText = result.risk_level === "CRITICAL" ? "!!!" :
                      result.risk_level === "HIGH" ? "WARN" :
                      result.risk_level === "MEDIUM" ? "MED" :
                      result.risk_level === "LOW" ? "LOW" : "SAFE";
    
    const badgeColor = result.risk_level === "CRITICAL" ? "#DC2626" :
                       result.risk_level === "HIGH" ? "#EA580C" :
                       result.risk_level === "MEDIUM" ? "#D97706" :
                       result.risk_level === "LOW" ? "#2563EB" : "#16A34A";

    if (tab?.id) {
      chrome.action.setBadgeText({ tabId: tab.id, text: badgeText });
      chrome.action.setBadgeBackgroundColor({ tabId: tab.id, color: badgeColor });
    }
  }
});
