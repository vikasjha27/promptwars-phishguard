(() => {
  "use strict";
  const $ = (id) => document.getElementById(id);
  const qsa = (s, el=document) => [...el.querySelectorAll(s)];

  const I18N = {
    en: { eyebrow:"Defence and Security", subtitle:"Personal Cybersecurity Dashboard", language:"Language",
      tab_triage:"Phishing & Scam Triage", tab_qr:"QR Scam Scanner", tab_password:"Password Checker", tab_academy:"Cyber Academy", tab_history:"Security History",
      triage_input:"Triage Input", triage_title:"Analyze a suspicious message", privacy_note:"Local analysis. Submitted URLs are never fetched.",
      presets_title:"One-click sample presets", presets_sub:"Load a scenario for instant evaluation.",
      preset_bank:"Bank KYC / OTP SMS Scam", preset_lookalike:"Lookalike Login URL", preset_intern:"Fake Internship Fee Offer", preset_meeting:"Normal Meeting Reminder",
      label_message:"Suspicious message text", help_message:"Email/SMS/WhatsApp content. URLs are extracted and defanged automatically. Ctrl+Enter to analyze.",
      label_url:"Standalone URL (optional)", help_url:"Add a URL if it is separate from the message.", label_sender:"Sender context", help_sender:"Helps detect context mismatch.",
      btn_analyze:"Analyze Risk", btn_clear:"Clear", triage_result:"Triage Result", risk_assessment:"Risk assessment", btn_download:"Download JSON", btn_copy:"Copy Triage Report",
      no_analysis:"No analysis yet", no_analysis_desc:"Paste a message, use a preset, and run analysis to see the risk score, indicators, and safe actions.",
      risk_score:"Risk Score", confidence:"Confidence", flagged_evidence:"Matched Evidence", indicators:"Extracted Indicators", reasons:"Why this was flagged", actions:"Recommended Actions", safe_reply:"Safe Reply / Reporting Note",
      verdict_safe:"Safe", verdict_susp:"Suspicious", verdict_high:"High Risk",
      qr_module:"QR Module", qr_title:"QR Scam Scanner", qr_privacy:"QR decoding runs locally in your browser. URLs are never opened automatically.", safety_warning:"Safety warning:",
      qr_warning:"Never auto-open scanned links. Review the decoded content and triage it before visiting any URL.", qr_upload:"Upload QR image", qr_upload_help:"Uses BarcodeDetector when supported; otherwise paste decoded text below.",
      qr_demo:"Load Suspicious QR Demo", qr_decoded:"Decoded QR text / URL (fallback)", qr_scan:"Decode & Analyze", qr_result:"QR Triage Result",
      pw_module:"Local Tool", pw_title:"Password Checker", pw_privacy:"100% client-side. Passwords are never transmitted or stored.", pw_label:"Enter password to evaluate",
      pw_help:"Checked locally for length, variety, repeats, sequences, and common weak passwords.", pw_tips:"Improvement tips", pw_tip_default:"Enter a password to see tips.",
      pw_weak:"Weak", pw_medium:"Medium", pw_strong:"Strong",
      ac_module:"Learn", ac_title:"Cyber Academy", ac_desc:"Answer 4 quick questions on phishing, OTP, UPI, and password safety. Get instant explanations.", ac_reset:"Reset Quiz",
      hist_module:"Local Only", hist_title:"Security History", hist_consent:"Opt in to store scan summaries in this browser (localStorage)", hist_filter:"Filter risk", hist_all:"All", hist_clear:"Clear History",
      footer:"PhishGuard AI performs deterministic local triage. It does not fetch submitted URLs, decode QR remotely, or transmit passwords. Not a replacement for security operations."
    },
    hi: { eyebrow:"रक्षा और सुरक्षा", subtitle:"व्यक्तिगत साइबर सुरक्षा डैशबोर्ड", language:"भाषा",
      tab_triage:"फ़िशिंग और स्कैम ट्रायेज", tab_qr:"QR स्कैम स्कैनर", tab_password:"पासवर्ड चेकर", tab_academy:"साइबर अकादमी", tab_history:"सुरक्षा इतिहास",
      triage_input:"ट्रायेज इनपुट", triage_title:"संदिग्ध संदेश का विश्लेषण करें", privacy_note:"स्थानीय विश्लेषण। सबमिट किए गए URL कभी नहीं खोले जाते।",
      presets_title:"एक-क्लिक नमूना प्रीसेट", presets_sub:"तुरंत मूल्यांकन के लिए परिदृश्य लोड करें।",
      preset_bank:"बैंक KYC / OTP SMS स्कैम", preset_lookalike:"नकली लॉगिन URL", preset_intern:"फर्जी इंटर्नशिप शुल्क ऑफर", preset_meeting:"सामान्य मीटिंग रिमाइंडर",
      label_message:"संदिग्ध संदेश टेक्स्ट", help_message:"ईमेल/SMS/WhatsApp सामग्री। URL स्वचालित रूप से निकाले और डिफैंग किए जाते हैं। Ctrl+Enter से विश्लेषण करें।",
      label_url:"अलग URL (वैकल्पिक)", help_url:"यदि URL संदेश से अलग है तो यहाँ जोड़ें।", label_sender:"प्रेषक संदर्भ", help_sender:"संदर्भ बेमेल पहचानने में मदद करता है।",
      btn_analyze:"जोखिम विश्लेषण", btn_clear:"साफ़ करें", triage_result:"ट्रायेज परिणाम", risk_assessment:"जोखिम मूल्यांकन", btn_download:"JSON डाउनलोड", btn_copy:"रिपोर्ट कॉपी करें",
      no_analysis:"अभी तक कोई विश्लेषण नहीं", no_analysis_desc:"संदेश पेस्ट करें या प्रीसेट चुनें और विश्लेषण चलाएँ।",
      risk_score:"जोखिम स्कोर", confidence:"विश्वास", flagged_evidence:"मिलान प्रमाण", indicators:"निकाले गए संकेतक", reasons:"इसे क्यों फ्लैग किया गया", actions:"अनुशंसित कार्रवाई", safe_reply:"सुरक्षित उत्तर / रिपोर्ट नोट",
      verdict_safe:"सुरक्षित", verdict_susp:"संदिग्ध", verdict_high:"उच्च जोखिम",
      qr_module:"QR मॉड्यूल", qr_title:"QR स्कैम स्कैनर", qr_privacy:"QR डिकोडिंग आपके ब्राउज़र में स्थानीय रूप से होती है। URL स्वतः नहीं खोले जाते।", safety_warning:"सुरक्षा चेतावनी:",
      qr_warning:"स्कैन किए लिंक स्वतः न खोलें। किसी भी URL पर जाने से पहले सामग्री की जाँच करें।", qr_upload:"QR इमेज अपलोड करें", qr_upload_help:"समर्थित होने पर BarcodeDetector उपयोग होता है; अन्यथा नीचे टेक्स्ट पेस्ट करें।",
      qr_demo:"संदिग्ध QR डेमो लोड करें", qr_decoded:"डिकोड किया QR टेक्स्ट / URL (फॉलबैक)", qr_scan:"डिकोड और विश्लेषण", qr_result:"QR ट्रायेज परिणाम",
      pw_module:"स्थानीय टूल", pw_title:"पासवर्ड चेकर", pw_privacy:"100% क्लाइंट-साइड। पासवर्ड कभी भेजे या संग्रहीत नहीं होते।", pw_label:"मूल्यांकन के लिए पासवर्ड दर्ज करें",
      pw_help:"लंबाई, विविधता, दोहराव, क्रम और सामान्य कमजोर पासवर्ड की स्थानीय जाँच।", pw_tips:"सुधार सुझाव", pw_tip_default:"सुझाव देखने के लिए पासवर्ड दर्ज करें।",
      pw_weak:"कमज़ोर", pw_medium:"मध्यम", pw_strong:"मज़बूत",
      ac_module:"सीखें", ac_title:"साइबर अकादमी", ac_desc:"फ़िशिंग, OTP, UPI और पासवर्ड सुरक्षा पर 4 प्रश्न। तुरंत स्पष्टीकरण पाएँ।", ac_reset:"क्विज़ रीसेट",
      hist_module:"केवल स्थानीय", hist_title:"सुरक्षा इतिहास", hist_consent:"इस ब्राउज़र में स्कैन सारांश संग्रहीत करने की सहमति दें (localStorage)", hist_filter:"जोखिम फ़िल्टर", hist_all:"सभी", hist_clear:"इतिहास साफ़ करें",
      footer:"PhishGuard AI स्थानीय ट्रायेज करता है। यह URL नहीं खोलता, QR दूरस्थ डिकोड नहीं करता, और पासवर्ड नहीं भेजता।"
    },
    kn: { eyebrow:"ರಕ್ಷಣೆ ಮತ್ತು ಭದ್ರತೆ", subtitle:"ವೈಯಕ್ತಿಕ ಸೈಬರ್ ಭದ್ರತಾ ಡ್ಯಾಶ್‌ಬೋರ್ಡ್", language:"ಭಾಷೆ",
      tab_triage:"ಫಿಷಿಂಗ್ ಮತ್ತು ವಂಚನೆ ಟ್ರಿಯಾಜ್", tab_qr:"QR ವಂಚನೆ ಸ್ಕ್ಯಾನರ್", tab_password:"ಪಾಸ್‌ವರ್ಡ್ ಪರಿಶೀಲಕ", tab_academy:"ಸೈಬರ್ ಅಕಾಡೆಮಿ", tab_history:"ಭದ್ರತಾ ಇತಿಹಾಸ",
      triage_input:"ಟ್ರಿಯಾಜ್ ಇನ್‌ಪುಟ್", triage_title:"ಸಂದೇಹಾಸ್ಪದ ಸಂದೇಶವನ್ನು ವಿಶ್ಲೇಷಿಸಿ", privacy_note:"ಸ್ಥಳೀಯ ವಿಶ್ಲೇಷಣೆ. ಸಲ್ಲಿಸಿದ URL ಗಳನ್ನು ಎಂದಿಗೂ ತೆರೆಯಲಾಗುವುದಿಲ್ಲ.",
      presets_title:"ಒಂದು-ಕ್ಲಿಕ್ ಮಾದರಿ ಪ್ರೀಸೆಟ್‌ಗಳು", presets_sub:"ತಕ್ಷಣ ಮೌಲ್ಯಮಾಪನಕ್ಕಾಗಿ ದೃಶ್ಯವನ್ನು ಲೋಡ್ ಮಾಡಿ.",
      preset_bank:"ಬ್ಯಾಂಕ್ KYC / OTP SMS ವಂಚನೆ", preset_lookalike:"ನಕಲಿ ಲಾಗಿನ್ URL", preset_intern:"ನಕಲಿ ಇಂಟರ್ನ್‌ಶಿಪ್ ಶುಲ್ಕ ಆಫರ್", preset_meeting:"ಸಾಮಾನ್ಯ ಸಭೆ ಜ್ಞಾಪನೆ",
      label_message:"ಸಂದೇಹಾಸ್ಪದ ಸಂದೇಶ ಪಠ್ಯ", help_message:"ಇಮೇಲ್/SMS/WhatsApp ವಿಷಯ. URL ಗಳು ಸ್ವಯಂಚಾಲಿತವಾಗಿ ಹೊರತೆಗೆದು ಡಿಫ್ಯಾಂಗ್ ಆಗುತ್ತವೆ. Ctrl+Enter ವಿಶ್ಲೇಷಿಸಿ.",
      label_url:"ಪ್ರತ್ಯೇಕ URL (ಐಚ್ಛಿಕ)", help_url:"URL ಸಂದೇಶದಿಂದ ಬೇರೆ ಇದ್ದರೆ ಇಲ್ಲಿ ಸೇರಿಸಿ.", label_sender:"ಕಳುಹಿಸುವವರ ಸಂದರ್ಭ", help_sender:"ಸಂದರ್ಭ ಹೊಂದಾಣಿಕೆ ತಪ್ಪು ಪತ್ತೆ ಮಾಡಲು ಸಹಾಯ.",
      btn_analyze:"ಅಪಾಯ ವಿಶ್ಲೇಷಿಸಿ", btn_clear:"ತೆರವುಗೊಳಿಸಿ", triage_result:"ಟ್ರಿಯಾಜ್ ಫಲಿತಾಂಶ", risk_assessment:"ಅಪಾಯ ಮೌಲ್ಯಮಾಪನ", btn_download:"JSON ಡೌನ್‌ಲೋಡ್", btn_copy:"ವರದಿ ನಕಲಿಸಿ",
      no_analysis:"ಇನ್ನೂ ವಿಶ್ಲೇಷಣೆ ಇಲ್ಲ", no_analysis_desc:"ಸಂದೇಶ ಅಂಟಿಸಿ ಅಥವಾ ಪ್ರೀಸೆಟ್ ಬಳಸಿ ವಿಶ್ಲೇಷಣೆ ನಡೆಸಿ.",
      risk_score:"ಅಪಾಯ ಅಂಕ", confidence:"ವಿಶ್ವಾಸ", flagged_evidence:"ಪತ್ತೆಯಾದ ಸಾಕ್ಷ್ಯ", indicators:"ಹೊರತೆಗೆದ ಸೂಚಕಗಳು", reasons:"ಇದನ್ನು ಏಕೆ ಫ್ಲ್ಯಾಗ್ ಮಾಡಲಾಗಿದೆ", actions:"ಶಿಫಾರಸು ಕ್ರಮಗಳು", safe_reply:"ಸುರಕ್ಷಿತ ಉತ್ತರ / ವರದಿ ಟಿಪ್ಪಣಿ",
      verdict_safe:"ಸುರಕ್ಷಿತ", verdict_susp:"ಸಂದೇಹಾಸ್ಪದ", verdict_high:"ಅತಿ ಅಪಾಯ",
      qr_module:"QR ಘಟಕ", qr_title:"QR ವಂಚನೆ ಸ್ಕ್ಯಾನರ್", qr_privacy:"QR ಡಿಕೋಡಿಂಗ್ ನಿಮ್ಮ ಬ್ರೌಸರ್‌ನಲ್ಲಿ ಸ್ಥಳೀಯವಾಗಿ ನಡೆಯುತ್ತದೆ. URL ಸ್ವಯಂಚಾಲಿತವಾಗಿ ತೆರೆಯುವುದಿಲ್ಲ.", safety_warning:"ಭದ್ರತಾ ಎಚ್ಚರಿಕೆ:",
      qr_warning:"ಸ್ಕ್ಯಾನ್ ಮಾಡಿದ ಲಿಂಕ್‌ಗಳನ್ನು ಸ್ವಯಂಚಾಲಿತವಾಗಿ ತೆರೆಯಬೇಡಿ. ಯಾವುದೇ URL ಗೆ ಹೋಗುವ ಮೊದಲು ವಿಷಯವನ್ನು ಪರಿಶೀಲಿಸಿ.", qr_upload:"QR ಚಿತ್ರ ಅಪ್‌ಲೋಡ್", qr_upload_help:"ಬೆಂಬಲಿಸಿದರೆ BarcodeDetector ಬಳಸುತ್ತದೆ; ಇಲ್ಲದಿದ್ದರೆ ಕೆಳಗೆ ಪಠ್ಯ ಅಂಟಿಸಿ.",
      qr_demo:"ಸಂದೇಹಾಸ್ಪದ QR ಡೆಮೋ ಲೋಡ್", qr_decoded:"ಡಿಕೋಡ್ ಮಾಡಿದ QR ಪಠ್ಯ / URL (ಫಾಲ್‌ಬ್ಯಾಕ್)", qr_scan:"ಡಿಕೋಡ್ ಮತ್ತು ವಿಶ್ಲೇಷಿಸಿ", qr_result:"QR ಟ್ರಿಯಾಜ್ ಫಲಿತಾಂಶ",
      pw_module:"ಸ್ಥಳೀಯ ಸಾಧನ", pw_title:"ಪಾಸ್‌ವರ್ಡ್ ಪರಿಶೀಲಕ", pw_privacy:"100% ಕ್ಲೈಂಟ್-ಸೈಡ್. ಪಾಸ್‌ವರ್ಡ್‌ಗಳನ್ನು ಎಂದಿಗೂ ಕಳುಹಿಸಲಾಗುವುದಿಲ್ಲ ಅಥವಾ ಸಂಗ್ರಹಿಸಲಾಗುವುದಿಲ್ಲ.", pw_label:"ಮೌಲ್ಯಮಾಪನಕ್ಕೆ ಪಾಸ್‌ವರ್ಡ್ ನಮೂದಿಸಿ",
      pw_help:"ಉದ್ದ, ವೈವಿಧ್ಯ, ಪುನರಾವೃತ್ತಿ, ಕ್ರಮ ಮತ್ತು ಸಾಮಾನ್ಯ ದುರ್ಬಲ ಪಾಸ್‌ವರ್ಡ್‌ಗಳ ಸ್ಥಳೀಯ ಪರಿಶೀಲನೆ.", pw_tips:"ಸುಧಾರಣಾ ಸಲಹೆಗಳು", pw_tip_default:"ಸಲಹೆಗಳನ್ನು ನೋಡಲು ಪಾಸ್‌ವರ್ಡ್ ನಮೂದಿಸಿ.",
      pw_weak:"ದುರ್ಬಲ", pw_medium:"ಮಧ್ಯಮ", pw_strong:"ಬಲವಾದ",
      ac_module:"ಕಲಿಯಿರಿ", ac_title:"ಸೈಬರ್ ಅಕಾಡೆಮಿ", ac_desc:"ಫಿಷಿಂಗ್, OTP, UPI ಮತ್ತು ಪಾಸ್‌ವರ್ಡ್ ಭದ್ರತೆಯ ಮೇಲೆ 4 ಪ್ರಶ್ನೆಗಳು. ತಕ್ಷಣ ವಿವರಣೆ ಪಡೆಯಿರಿ.", ac_reset:"ಕ್ವಿಜ್ ಮರುಹೊಂದಿಸಿ",
      hist_module:"ಸ್ಥಳೀಯ ಮಾತ್ರ", hist_title:"ಭದ್ರತಾ ಇತಿಹಾಸ", hist_consent:"ಈ ಬ್ರೌಸರ್‌ನಲ್ಲಿ ಸ್ಕ್ಯಾನ್ ಸಾರಾಂಶಗಳನ್ನು ಸಂಗ್ರಹಿಸಲು ಒಪ್ಪಿಗೆ (localStorage)", hist_filter:"ಅಪಾಯ ಫಿಲ್ಟರ್", hist_all:"ಎಲ್ಲಾ", hist_clear:"ಇತಿಹಾಸ ತೆರವುಗೊಳಿಸಿ",
      footer:"PhishGuard AI ಸ್ಥಳೀಯ ಟ್ರಿಯಾಜ್ ಮಾಡುತ್ತದೆ. ಇದು URL ಗಳನ್ನು ತೆರೆಯುವುದಿಲ್ಲ, QR ಅನ್ನು ರಿಮೋಟ್ ಡಿಕೋಡ್ ಮಾಡುವುದಿಲ್ಲ, ಅಥವಾ ಪಾಸ್‌ವರ್ಡ್ ಕಳುಹಿಸುವುದಿಲ್ಲ."
    }
  };

  const REC_MAP = [
    [/do not reply, click links, scan qr codes, or share otps/i, {en:"Do not reply, click links, scan QR codes, or share OTPs, passwords, or personal details.", hi:"उत्तर न दें, लिंक पर क्लिक न करें, QR स्कैन न करें, और OTP/पासवर्ड/व्यक्तिगत जानकारी साझा न करें।", kn:"ಉತ್ತರಿಸಬೇಡಿ, ಲಿಂಕ್ ಕ್ಲಿಕ್ ಮಾಡಬೇಡಿ, QR ಸ್ಕ್ಯಾನ್ ಮಾಡಬೇಡಿ, OTP/ಪಾಸ್‌ವರ್ಡ್/ವೈಯಕ್ತಿಕ ಮಾಹಿತಿ ಹಂಚಬೇಡಿ."}],
    [/verify the claim using the organization's official website/i, {en:"Verify the claim using the organization's official website or helpline, not the message link.", hi:"संदेश के लिंक के बजाय संगठन की आधिकारिक वेबसाइट या हेल्पलाइन से सत्यापित करें।", kn:"ಸಂದೇಶದ ಲಿಂಕ್ ಬದಲಿಗೆ ಸಂಸ್ಥೆಯ ಅಧಿಕೃತ ವೆಬ್‌ಸೈಟ್ ಅಥವಾ ಹೆಲ್ಪ್‌ಲೈನ್ ಮೂಲಕ ಪರಿಶೀಲಿಸಿ."}],
    [/report the message as phishing/i, {en:"Report the message as phishing/scam to your security team, carrier, or platform.", hi:"संदेश को फ़िशिंग/स्कैम के रूप में सुरक्षा टीम, कैरियर या प्लेटफ़ॉर्म को रिपोर्ट करें।", kn:"ಸಂದೇಶವನ್ನು ಫಿಷಿಂಗ್/ವಂಚನೆ ಎಂದು ಭದ್ರತಾ ತಂಡ, ಕ್ಯಾರಿಯರ್ ಅಥವಾ ಪ್ಲಾಟ್‌ಫಾರ್ಮ್‌ಗೆ ವರದಿ ಮಾಡಿ."}],
    [/if you already entered credentials/i, {en:"If you already entered credentials, change the password immediately and enable MFA from the official site.", hi:"यदि आपने क्रेडेंशियल दर्ज किए हैं, तुरंत पासवर्ड बदलें और आधिकारिक साइट से MFA सक्षम करें।", kn:"ನೀವು ರುಜುವಾತುಗಳನ್ನು ನಮೂದಿಸಿದ್ದರೆ, ತಕ್ಷಣ ಪಾಸ್‌ವರ್ಡ್ ಬದಲಿಸಿ ಮತ್ತು ಅಧಿಕೃತ ಸೈಟ್‌ನಿಂದ MFA ಸಕ್ರಿಯಗೊಳಿಸಿ."}],
    [/do not send money or approve payments/i, {en:"Do not send money or approve payments; confirm payment requests through a separate trusted channel.", hi:"पैसे न भेजें या भुगतान स्वीकृत न करें; अलग विश्वसनीय माध्यम से पुष्टि करें।", kn:"ಹಣ ಕಳುಹಿಸಬೇಡಿ ಅಥವಾ ಪಾವತಿ ಅನುಮೋದಿಸಬೇಡಿ; ಬೇರೆ ವಿಶ್ವಾಸಾರ್ಹ ಮಾರ್ಗದಲ್ಲಿ ದೃಢೀಕರಿಸಿ."}],
    [/treat the message with caution/i, {en:"Treat the message with caution and avoid clicking links until independently verified.", hi:"संदेश को सावधानी से लें और स्वतंत्र सत्यापन तक लिंक पर क्लिक न करें।", kn:"ಸಂದೇಶವನ್ನು ಎಚ್ಚರಿಕೆಯಿಂದ ಪರಿಗಣಿಸಿ ಮತ್ತು ಸ್ವತಂತ್ರ ಪರಿಶೀಲನೆ ತನಕ ಲಿಂಕ್ ಕ್ಲಿಕ್ ಮಾಡಬೇಡಿ."}],
    [/contact the sender through a known official channel/i, {en:"Contact the sender through a known official channel to confirm legitimacy.", hi:"वैधता की पुष्टि के लिए ज्ञात आधिकारिक माध्यम से संपर्क करें।", kn:"ನೈಜತೆಯನ್ನು ದೃಢೀಕರಿಸಲು ತಿಳಿದ ಅಧಿಕೃತ ಮಾರ್ಗದಲ್ಲಿ ಸಂಪರ್ಕಿಸಿ."}],
    [/if the message asks for money, credentials, or urgency/i, {en:"If the message asks for money, credentials, or urgency, report it to your security/helpdesk team.", hi:"यदि संदेश पैसे, क्रेडेंशियल या तात्कालिकता माँगे, तो सुरक्षा/हेल्पडेस्क को रिपोर्ट करें।", kn:"ಸಂದೇಶ ಹಣ, ರುಜುವಾತುಗಳು ಅಥವಾ ತುರ್ತು ಕೇಳಿದರೆ ಭದ್ರತಾ/ಹೆಲ್ಪ್‌ಡೆಸ್ಕ್‌ಗೆ ವರದಿ ಮಾಡಿ."}],
    [/use the official app or bookmarked website/i, {en:"Use the official app or bookmarked website instead of any link provided in the message.", hi:"संदेश के लिंक के बजाय आधिकारिक ऐप या बुकमार्क की गई वेबसाइट का उपयोग करें।", kn:"ಸಂದೇಶದ ಲಿಂಕ್ ಬದಲಿಗೆ ಅಧಿಕೃತ ಅಪ್ಲಿಕೇಶನ್ ಅಥವಾ ಬುಕ್‌ಮಾರ್ಕ್ ಮಾಡಿದ ವೆಬ್‌ಸೈಟ್ ಬಳಸಿ."}],
    [/no immediate phishing indicators were detected/i, {en:"No immediate phishing indicators were detected, but remain cautious with unexpected requests.", hi:"तुरंत कोई फ़िशिंग संकेत नहीं मिला, लेकिन अप्रत्याशित अनुरोधों से सावधान रहें।", kn:"ತಕ್ಷಣದ ಫಿಷಿಂಗ್ ಸೂಚಕಗಳು ಕಂಡುಬಂದಿಲ್ಲ, ಆದರೆ ಅನಿರೀಕ್ಷಿತ ವಿನಂತಿಗಳಲ್ಲಿ ಎಚ್ಚರದಿಂದಿರಿ."}],
    [/verify sensitive requests through official channels/i, {en:"Verify sensitive requests through official channels if context changes.", hi:"संदर्भ बदलने पर संवेदनशील अनुरोधों को आधिकारिक माध्यम से सत्यापित करें।", kn:"ಸಂದರ್ಭ ಬದಲಾದರೆ ಸಂವೇದನಾಶೀಲ ವಿನಂತಿಗಳನ್ನು ಅಧಿಕೃತ ಮಾರ್ಗಗಳಲ್ಲಿ ಪರಿಶೀಲಿಸಿ."}],
    [/do not click unknown links or download unexpected attachments/i, {en:"Do not click unknown links or download unexpected attachments.", hi:"अज्ञात लिंक पर क्लिक न करें या अप्रत्याशित अटैचमेंट डाउनलोड न करें।", kn:"ಅಜ್ಞಾತ ಲಿಂಕ್‌ಗಳನ್ನು ಕ್ಲಿಕ್ ಮಾಡಬೇಡಿ ಅಥವಾ ಅನಿರೀಕ್ಷಿತ ಲಗತ್ತುಗಳನ್ನು ಡೌನ್‌ಲೋಡ್ ಮಾಡಬೇಡಿ."}]
  ];

  let lang = localStorage.getItem("pg-lang") || "en";
  let lastReport = null;
  const HISTORY_KEY = "pg-scan-history";
  const CONSENT_KEY = "pg-history-consent";

  function t(key){ return (I18N[lang] && I18N[lang][key]) || I18N.en[key] || key; }
  function verdictLabel(v){ const k=(v||"").toLowerCase(); if(k==="high risk") return t("verdict_high"); if(k==="suspicious") return t("verdict_susp"); return t("verdict_safe"); }
  function verdictClass(v){ const k=(v||"").toLowerCase(); if(k==="high risk") return "high-risk"; if(k==="suspicious") return "suspicious"; return "safe"; }
  function translateRec(text){
    for(const [re,map] of REC_MAP){ if(re.test(text)) return map[lang] || map.en; }
    return text;
  }
  function applyI18n(){
    document.documentElement.lang = lang;
    qsa("[data-i18n]").forEach(el => { const k=el.getAttribute("data-i18n"); if(I18N[lang][k]) el.textContent = I18N[lang][k]; });
    qsa("[data-i18n-placeholder]").forEach(el => { const k=el.getAttribute("data-i18n-placeholder"); if(I18N[lang][k]) el.placeholder = I18N[lang][k]; });
    $("lang-select").value = lang;
    // update verdict text if result shown
    if(lastReport){ $("verdict-text").textContent = verdictLabel(lastReport.verdict); renderActions(lastReport.recommended_actions||[]); }
    renderHistory();
    renderQuiz();
    updatePw();
  }

  // Theme
  function setTheme(theme){ document.documentElement.setAttribute("data-theme",theme); const light=theme==="light"; $("theme-toggle").setAttribute("aria-pressed",String(light)); $("theme-label").textContent=light?"Light":"Dark"; try{localStorage.setItem("pg-theme",theme);}catch{} }
  function initTheme(){ let s=null; try{s=localStorage.getItem("pg-theme")}catch{} if(s==="light"||s==="dark") return setTheme(s); setTheme(matchMedia("(prefers-color-scheme: light)").matches?"light":"dark"); }

  // Nav
  qsa(".nav-tab").forEach(btn => btn.addEventListener("click", () => {
    qsa(".nav-tab").forEach(b=>{b.classList.remove("active"); b.removeAttribute("aria-current");});
    btn.classList.add("active"); btn.setAttribute("aria-current","page");
    const tab=btn.dataset.tab;
    qsa(".tab-panel").forEach(p=>p.classList.add("hidden"));
    $("tab-"+tab).classList.remove("hidden");
  }));

  $("lang-select").addEventListener("change", e => { lang=e.target.value; try{localStorage.setItem("pg-lang",lang)}catch{} applyI18n(); });
  $("theme-toggle").addEventListener("click", () => setTheme((document.documentElement.getAttribute("data-theme")==="dark")?"light":"dark"));

  function clearChildren(el){ while(el.firstChild) el.removeChild(el.firstChild); }
  function makePill(text, cls=""){ const s=document.createElement("span"); s.className="pill"+(cls?" "+cls:""); s.textContent=text; return s; }
  function makeLi(text){ const li=document.createElement("li"); li.textContent=text; return li; }
  function setStatus(id,msg,err){ const el=$(id); el.textContent=msg||""; el.className="form-status"+(err?" error":""); }

  // ===== TRIAGE =====
  const PRESETS = {
    bank:{text:"URGENT: Your SBI account will be suspended within 24 hours due to incomplete KYC. Verify immediately to avoid account blockage. Share your OTP and PIN with our support agent when asked. Click: http://sbi-kyc-secure-update[.]xyz/login",url:"",sender:"Bank"},
    lookalike:{text:"Please verify your account login to continue using online banking services.",url:"hxxp://sbi-kyc-verify[.]xyz/login",sender:"Bank"},
    internship:{text:"Congratulations! You've been selected for a remote internship at GlobalTech. To confirm your slot, pay a refundable registration fee of Rs. 1,999 today. Limited seats, act now. Reply with your details and payment screenshot.",url:"",sender:"Employer"},
    safe:{text:"Hi team, reminder that our college project meeting is tomorrow at 10:00 AM in Lab 3. Please bring your progress slides. See you there!",url:"",sender:"Colleague"}
  };

  function renderActions(actions){
    const el=$("actions"); clearChildren(el);
    (actions||[]).forEach(a=>el.appendChild(makeLi(translateRec(String(a)))));
  }
  function renderResult(data){
    lastReport = data;
    $("result-empty").classList.add("hidden");
    $("result-content").classList.remove("hidden");
    $("copy-report").disabled=false; $("copy-report").removeAttribute("aria-disabled");
    $("download-report").disabled=false; $("download-report").removeAttribute("aria-disabled");
    const score=Number(data.risk_score||0), vc=verdictClass(data.verdict);
    $("risk-score").textContent=String(score);
    $("gauge-bar").style.width=Math.max(0,Math.min(100,score))+"%";
    $("gauge-bar").className="gauge-bar "+vc;
    $("verdict-badge").className="verdict-badge "+vc;
    $("verdict-icon").textContent=vc==="high-risk"?"!":vc==="suspicious"?"?":"✓";
    $("verdict-text").textContent=verdictLabel(data.verdict);
    $("confidence-text").textContent=data.confidence||"Medium";
    $("score-sr").textContent=`${t("risk_score")} ${score}/100. ${verdictLabel(data.verdict)}.`;
    const ev=$("evidence"); clearChildren(ev); const sn=data.matched_snippets||[]; if(!sn.length) ev.appendChild(makePill("None")); else sn.forEach(s=>ev.appendChild(makePill(String(s),"evidence")));
    const ind=$("indicators"); clearChildren(ind); const inds=data.extracted_indicators||[]; if(!inds.length) ind.appendChild(makePill("None")); else inds.forEach(i=>{const p=makePill(String(i)); const l=i.toLowerCase(); if(l.startsWith("url:")||l.startsWith("domain:")) p.classList.add("url"); if(l.startsWith("tactic:")) p.classList.add("tactic"); ind.appendChild(p);});
    const rs=$("reasons"); clearChildren(rs); (data.reasons||[]).forEach(r=>rs.appendChild(makeLi(String(r))));
    renderActions(data.recommended_actions||[]);
    const reply=data.safe_reply_template; if(reply){$("reply-block").classList.remove("hidden"); $("safe-reply").textContent=String(reply);} else {$("reply-block").classList.add("hidden"); $("safe-reply").textContent="";}
  }

  function reportAsText(data){
    if(!data) return "";
    const lines=["PhishGuard AI — Triage Report",`Verdict: ${verdictLabel(data.verdict)} (${data.verdict})`,`Risk Score: ${data.risk_score}/100`,`Confidence: ${data.confidence}`,"","Flagged Evidence:",...((data.matched_snippets&&data.matched_snippets.length)?data.matched_snippets:["None"]).map(i=>`- ${i}`),"","Extracted Indicators:",...(data.extracted_indicators||[]).map(i=>`- ${i}`),"","Reasons:",...(data.reasons||[]).map(r=>`- ${r}`),"","Recommended Actions:",...(data.recommended_actions||[]).map(a=>`- ${translateRec(a)}`)];
    if(data.safe_reply_template) lines.push("","Safe Reply / Reporting Note:",data.safe_reply_template);
    return lines.join("\n");
  }
  async function copyReport(){
    const text=reportAsText(lastReport); if(!text) return;
    try{ await navigator.clipboard.writeText(text); setStatus("form-status","Copied report."); }
    catch{ const ta=document.createElement("textarea"); ta.value=text; ta.style.position="fixed"; ta.style.opacity="0"; document.body.appendChild(ta); ta.select(); try{document.execCommand("copy"); setStatus("form-status","Copied report.");}catch{setStatus("form-status","Copy failed.",true);} document.body.removeChild(ta); }
  }
  function downloadReport(){
    if(!lastReport) return;
    const blob=new Blob([JSON.stringify(lastReport,null,2)],{type:"application/json"});
    const a=document.createElement("a"); a.href=URL.createObjectURL(blob); a.download=`phishguard-triage-${Date.now()}.json`; document.body.appendChild(a); a.click(); a.remove(); URL.revokeObjectURL(a.href);
  }

  // History (opt-in)
  function hasConsent(){ return localStorage.getItem(CONSENT_KEY)==="1"; }
  function loadHistory(){ try{return JSON.parse(localStorage.getItem(HISTORY_KEY)||"[]")}catch{return[]} }
  function saveHistory(items){ try{localStorage.setItem(HISTORY_KEY, JSON.stringify(items.slice(0,50)));}catch{} }
  function addHistory(data,input){
    if(!hasConsent()) return;
    const items=loadHistory();
    items.unshift({ts:new Date().toISOString(), verdict:data.verdict, risk_score:data.risk_score, confidence:data.confidence, sender:input.sender||"Unknown", snippet:(input.text||input.url||"").slice(0,120)});
    saveHistory(items); renderHistory();
  }
  function renderHistory(){
    const list=$("history-list"); if(!list) return; clearChildren(list);
    const consent=$("history-consent"); if(consent) consent.checked=hasConsent();
    const filter=$("history-filter")?$("history-filter").value:"all";
    const items=loadHistory().filter(i=>filter==="all"||i.verdict===filter);
    if(!hasConsent()){ const p=document.createElement("p"); p.className="field-help"; p.textContent=t("hist_consent"); list.appendChild(p); return; }
    if(!items.length){ const p=document.createElement("p"); p.className="field-help"; p.textContent="No scan summaries stored."; list.appendChild(p); return; }
    items.forEach(i=>{
      const d=document.createElement("div"); d.className="history-item";
      const left=document.createElement("div");
      const chip=document.createElement("span"); const vc=verdictClass(i.verdict); chip.className="verdict-chip "+(vc==="high-risk"?"high":vc==="suspicious"?"susp":"safe"); chip.textContent=verdictLabel(i.verdict);
      left.appendChild(chip);
      const strong=document.createElement("strong"); strong.textContent=` ${i.risk_score}/100`; left.appendChild(strong);
      const meta=document.createElement("div"); meta.className="history-meta"; meta.textContent=`${new Date(i.ts).toLocaleString()} · ${i.sender||"Unknown"} · ${(i.snippet||"").replace(/\s+/g," ").slice(0,80)}`; left.appendChild(meta);
      d.appendChild(left); list.appendChild(d);
    });
  }

  async function analyze(inputOverride){
    const input=inputOverride || {text:$("message-text").value.trim(), url:$("url-input").value.trim(), sender:$("sender-input").value};
    if(!input.text && !input.url){ setStatus("form-status","Please provide a message or URL.",true); return null; }
    $("analyze-btn").disabled=true; $("analyze-btn").textContent="..."; setStatus("form-status","Analyzing...");
    try{
      const resp=await fetch("/api/analyze",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(input)});
      const data=await resp.json().catch(()=>null);
      if(!resp.ok) throw new Error((data&&data.detail)||"Analysis failed");
      renderResult(data); addHistory(data,input); setStatus("form-status","Analysis complete.");
      return data;
    }catch(e){ setStatus("form-status",e.message||"Error",true); return null; }
    finally{ $("analyze-btn").disabled=false; $("analyze-btn").innerHTML='<span aria-hidden="true">⚡</span> <span data-i18n="btn_analyze">'+t("btn_analyze")+'</span>'; }
  }

  $("analyze-form").addEventListener("submit", e=>{e.preventDefault(); analyze();});
  $("clear-btn").addEventListener("click", ()=>{ $("analyze-form").reset(); $("sender-input").value="Unknown"; lastReport=null; $("result-content").classList.add("hidden"); $("result-empty").classList.remove("hidden"); $("copy-report").disabled=true; $("download-report").disabled=true; setStatus("form-status",""); });
  $("copy-report").addEventListener("click", copyReport);
  $("download-report").addEventListener("click", downloadReport);
  qsa("[data-preset]").forEach(btn=>btn.addEventListener("click", ()=>{ const p=PRESETS[btn.dataset.preset]; if(!p) return; $("message-text").value=p.text; $("url-input").value=p.url; $("sender-input").value=p.sender; setStatus("form-status","Preset loaded."); $("message-text").focus(); }));
  $("message-text").addEventListener("keydown", e=>{ if((e.ctrlKey||e.metaKey)&&e.key==="Enter"){ e.preventDefault(); analyze(); }});

  // History controls
  $("history-consent").addEventListener("change", e=>{ localStorage.setItem(CONSENT_KEY, e.target.checked?"1":"0"); if(!e.target.checked) setStatus("history-status","History storage disabled. Existing summaries kept until you clear them."); else setStatus("history-status","History storage enabled."); renderHistory(); });
  $("history-filter").addEventListener("change", renderHistory);
  $("history-clear").addEventListener("click", ()=>{ saveHistory([]); setStatus("history-status","History cleared."); renderHistory(); });

  // ===== QR SCANNER =====
  function renderMiniResult(container, data){
    clearChildren(container);
    const top=document.createElement("div"); top.className="score-meta";
    const badge=document.createElement("div"); const vc=verdictClass(data.verdict); badge.className="verdict-badge "+vc; badge.textContent=verdictLabel(data.verdict)+" - "+data.risk_score+"/100"; top.appendChild(badge);
    container.appendChild(top);
    const ev=document.createElement("div"); ev.className="pill-list"; (data.matched_snippets||[]).slice(0,6).forEach(s=>ev.appendChild(makePill(String(s),"evidence"))); if(!ev.childNodes.length) ev.appendChild(makePill("None")); container.appendChild(ev);
    const ul=document.createElement("ul"); ul.className="action-list"; (data.recommended_actions||[]).slice(0,4).forEach(a=>ul.appendChild(makeLi(translateRec(String(a))))); container.appendChild(ul);
  }
  async function decodeQrFile(file){
    if(!("BarcodeDetector" in window)) throw new Error("BarcodeDetector not supported. Paste decoded QR text below.");
    const det=new BarcodeDetector({formats:["qr_code"]});
    const bmp=await createImageBitmap(file);
    const codes=await det.detect(bmp); bmp.close && bmp.close();
    if(!codes.length) throw new Error("No QR code detected. Try a clearer image or paste decoded text.");
    return (codes[0].rawValue||"").trim();
  }
  $("qr-demo").addEventListener("click", ()=>{ $("qr-text").value="http://sbi-kyc-verify[.]xyz/login?session=urgent"; setStatus("qr-status","Suspicious QR demo loaded. Click Decode & Analyze."); });
  $("qr-clear").addEventListener("click", ()=>{ $("qr-file").value=""; $("qr-text").value=""; $("qr-result").classList.add("hidden"); clearChildren($("qr-result-body")); setStatus("qr-status",""); });
  $("qr-scan-btn").addEventListener("click", async ()=>{
    setStatus("qr-status","Processing QR locally...");
    $("qr-result").classList.add("hidden");
    try{
      let decoded=$("qr-text").value.trim();
      const file=$("qr-file").files && $("qr-file").files[0];
      if(file){ try{ decoded=await decodeQrFile(file); $("qr-text").value=decoded; } catch(e){ if(!decoded) throw e; setStatus("qr-status",e.message+" Using pasted text.",true); } }
      if(!decoded){ setStatus("qr-status","Provide a QR image or paste decoded text/URL.",true); return; }
      // never auto-open; analyze as text/url
      const payload=/^(https?|hxxps?):\/\//i.test(decoded)||decoded.includes("[.]") ? {text:"QR decoded content", url:decoded, sender:"Unknown"} : {text:"QR decoded content: "+decoded, url:"", sender:"Unknown"};
      setStatus("qr-status","Decoded locally. Analyzing payload (URLs not opened)... ");
      const resp=await fetch("/api/analyze",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(payload)});
      const data=await resp.json();
      if(!resp.ok) throw new Error(data.detail||"Analysis failed");
      $("qr-result").classList.remove("hidden"); renderMiniResult($("qr-result-body"), data); addHistory(data,payload);
      setStatus("qr-status","QR decoded and analyzed locally. Do not open links automatically.");
    }catch(e){ setStatus("qr-status",e.message||"QR scan failed",true); }
  });

  // ===== PASSWORD CHECKER =====
  const COMMON_PW = new Set(["password","123456","12345678","qwerty","abc123","password1","admin","letmein","welcome","iloveyou","111111","123123","qwerty123","1q2w3e4r","passw0rd"]);
  function pwScore(pw){
    const tips=[]; let score=0;
    if(!pw) return {score:0,label:"pw_weak",tips:[t("pw_tip_default")]};
    if(pw.length>=12) score+=30; else if(pw.length>=8) {score+=15; tips.push(lang==="hi"?"पासवर्ड 12+ अक्षर का करें।":lang==="kn"?"ಪಾಸ್‌ವರ್ಡ್ 12+ ಅಕ್ಷರ ಮಾಡಿ.":"Use 12+ characters.");} else {tips.push(lang==="hi"?"पासवर्ड कम से कम 8-12 अक्षर का रखें।":lang==="kn"?"ಕನಿಷ್ಠ 8-12 ಅಕ್ಷರ ಬಳಸಿ.":"Use at least 8-12 characters.");}
    const hasL=/[a-z]/.test(pw), hasU=/[A-Z]/.test(pw), hasD=/\d/.test(pw), hasS=/[^A-Za-z0-9]/.test(pw);
    const variety=[hasL,hasU,hasD,hasS].filter(Boolean).length; score+=variety*12;
    if(variety<3) tips.push(lang==="hi"?"बड़े/छोटे अक्षर, संख्या और प्रतीक मिलाएँ।":lang==="kn"?"ದೊಡ್ಡ/ಸಣ್ಣ ಅಕ್ಷರ, ಸಂಖ್ಯೆ, ಚಿಹ್ನೆ ಮಿಶ್ರಣ ಮಾಡಿ.":"Mix upper/lower case, numbers, and symbols.");
    if(/(.)\1{2,}/.test(pw)){ score-=10; tips.push(lang==="hi"?"दोहराए गए अक्षर कम करें।":lang==="kn"?"ಪುನರಾವರ್ತಿತ ಅಕ್ಷರಗಳನ್ನು ಕಡಿಮೆ ಮಾಡಿ.":"Avoid repeated characters.");}
    if(/(abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz|012|123|234|345|456|567|678|789)/i.test(pw)){ score-=10; tips.push(lang==="hi"?"क्रमिक पैटर्न (123, abc) से बचें।":lang==="kn"?"ಕ್ರಮಬದ್ಧ ಮಾದರಿಗಳನ್ನು ತಪ್ಪಿಸಿ (123, abc).":"Avoid sequential patterns (123, abc).");}
    if(COMMON_PW.has(pw.toLowerCase())){ score-=35; tips.push(lang==="hi"?"यह सामान्य कमजोर पासवर्ड है।":lang==="kn"?"ಇದು ಸಾಮಾನ್ಯ ದುರ್ಬಲ ಪಾಸ್‌ವರ್ಡ್.":"This is a common weak password.");}
    score=Math.max(0,Math.min(100,score));
    const label=score>=70?"pw_strong":score>=40?"pw_medium":"pw_weak";
    if(!tips.length) tips.push(lang==="hi"?"अच्छा पासवर्ड। इसे निजी रखें और MFA सक्षम करें।":lang==="kn"?"ಉತ್ತಮ ಪಾಸ್‌ವರ್ಡ್. ಖಾಸಗಿಯಾಗಿ ಇಡಿ ಮತ್ತು MFA ಸಕ್ರಿಯಗೊಳಿಸಿ.":"Good password. Keep it private and enable MFA.");
    return {score,label,tips};
  }
  function updatePw(){
    const pw=$("pw-input").value||"";
    const r=pwScore(pw);
    const m=$("pw-meter"); m.style.width=r.score+"%"; m.className="pw-meter "+(r.label==="pw_strong"?"strong":r.label==="pw_medium"?"medium":"weak");
    $("pw-verdict").textContent=t(r.label)+" ("+r.score+"/100)";
    const ul=$("pw-tips"); clearChildren(ul); r.tips.forEach(x=>ul.appendChild(makeLi(x)));
  }
  $("pw-input").addEventListener("input", updatePw);

  // ===== QUIZ =====
  const QUIZ = [
    {q:{en:"A bank SMS asks for your OTP to 'cancel a suspicious transaction'. What should you do?",hi:"बैंक SMS में संदिग्ध लेनदेन रद्द करने के लिए OTP माँगा गया है। क्या करें?",kn:"ಸಂದೇಹಾಸ್ಪದ ವಹಿವಾಟು ರದ್ದು ಮಾಡಲು ಬ್ಯಾಂಕ್ SMS OTP ಕೇಳುತ್ತದೆ. ಏನು ಮಾಡಬೇಕು?"},
     opts:{en:["Share OTP quickly","Ignore and verify via official bank app/helpline","Reply with account number"],hi:["तुरंत OTP साझा करें","अनदेखा करें और आधिकारिक बैंक ऐप/हेल्पलाइन से सत्यापित करें","खाता नंबर से जवाब दें"],kn:["OTP ತಕ್ಷಣ ಹಂಚಿಕೊಳ್ಳಿ","ನಿರ್ಲಕ್ಷಿಸಿ ಮತ್ತು ಅಧಿಕೃತ ಬ್ಯಾಂಕ್ ಅಪ್ಲಿಕೇಶನ್/ಹೆಲ್ಪ್‌ಲೈನ್ ಮೂಲಕ ಪರಿಶೀಲಿಸಿ","ಖಾತೆ ಸಂಖ್ಯೆಯೊಂದಿಗೆ ಉತ್ತರಿಸಿ"]},
     a:1, exp:{en:"Banks never ask for OTP to cancel transactions. Verify through official channels.",hi:"बैंक लेनदेन रद्द करने के लिए OTP नहीं माँगते। आधिकारिक माध्यम से सत्यापित करें।",kn:"ವಹಿವಾಟು ರದ್ದು ಮಾಡಲು ಬ್ಯಾಂಕ್ OTP ಕೇಳುವುದಿಲ್ಲ. ಅಧಿಕೃತ ಮಾರ್ಗದಲ್ಲಿ ಪರಿಶೀಲಿಸಿ."}},
    {q:{en:"You receive a QR code promising a refund. It asks you to approve a collect request/enter UPI PIN. This is:",hi:"रिफंड का वादा करने वाला QR कोड कलेक्ट रिक्वेस्ट स्वीकृत/UPI PIN दर्ज करने को कहता है। यह है:",kn:"ರಿಫಂಡ್ ವಾಗ್ದಾನ ಮಾಡುವ QR ಕೋಡ್ collect request ಅನುಮೋದಿಸಲು/UPI PIN ನಮೂದಿಸಲು ಕೇಳುತ್ತದೆ. ಇದು:"},
     opts:{en:["Normal refund process","Likely a UPI scam","Safe if QR looks official"],hi:["सामान्य रिफंड प्रक्रिया","संभवतः UPI स्कैम","सुरक्षित यदि QR आधिकारिक लगे"],kn:["ಸಾಮಾನ್ಯ ರಿಫಂಡ್ ಪ್ರಕ್ರಿಯೆ","ಬಹುಶಃ UPI ವಂಚನೆ","QR ಅಧಿಕೃತವಾಗಿ ಕಂಡರೆ ಸುರಕ್ಷಿತ"]},
     a:1, exp:{en:"You never enter UPI PIN to receive money. Collect/approve requests can steal funds.",hi:"पैसे पाने के लिए UPI PIN नहीं डालते। कलेक्ट/स्वीकृति अनुरोध पैसे चुरा सकते हैं।",kn:"ಹಣ ಪಡೆಯಲು UPI PIN ನಮೂದಿಸುವುದಿಲ್ಲ. Collect/approve ವಿನಂತಿಗಳು ಹಣ ಕದಿಯಬಹುದು."}},
    {q:{en:"Which password is strongest?",hi:"कौन सा पासवर्ड सबसे मज़बूत है?",kn:"ಯಾವ ಪಾಸ್‌ವರ್ಡ್ ಅತ್ಯಂತ ಬಲವಾಗಿದೆ?"},
     opts:{en:["Password@123","R7!mQ2#vL9$z","vikas1998"],hi:["Password@123","R7!mQ2#vL9$z","vikas1998"],kn:["Password@123","R7!mQ2#vL9$z","vikas1998"]},
     a:1, exp:{en:"Long, random passphrases/passwords with mixed character types are stronger.",hi:"लंबे, यादृच्छिक, मिश्रित वर्ण वाले पासवर्ड अधिक मजबूत होते हैं।",kn:"ದೀರ್ಘ, ಯಾದೃಚ್ಛಿಕ, ಮಿಶ್ರ ಅಕ್ಷರ ಪ್ರಕಾರಗಳ ಪಾಸ್‌ವರ್ಡ್ ಬಲವಾಗಿರುತ್ತದೆ."}},
    {q:{en:"An email from 'support@paypa1.com' asks you to verify your account urgently. Best action?",hi:"'support@paypa1.com' से ईमेल तुरंत खाता सत्यापित करने को कहता है। सर्वोत्तम कार्रवाई?",kn:"'support@paypa1.com' ಇಮೇಲ್ ತುರ್ತಾಗಿ ಖಾತೆ ಪರಿಶೀಲಿಸಲು ಕೇಳುತ್ತದೆ. ಉತ್ತಮ ಕ್ರಮ?"},
     opts:{en:["Click link and login","Check sender/domain carefully and verify via official site","Forward to friends"],hi:["लिंक पर क्लिक करें","प्रेषक/डोमेन जांचें और आधिकारिक साइट से सत्यापित करें","दोस्तों को फॉरवर्ड करें"],kn:["ಲಿಂಕ್ ಕ್ಲಿಕ್ ಮಾಡಿ","ಕಳುಹಿಸುವವರು/ಡೊಮೇನ್ ಜಾಗ್ರತೆಯಿಂದ ನೋಡಿ ಮತ್ತು ಅಧಿಕೃತ ಸೈಟ್ ಮೂಲಕ ಪರಿಶೀಲಿಸಿ","ಸ್ನೇಹಿತರಿಗೆ ಫಾರ್ವರ್ಡ್ ಮಾಡಿ"]},
     a:1, exp:{en:"Lookalike domains and urgency are phishing signs. Use official sites, not email links.",hi:"नकली डोमेन और तात्कालिकता फ़िशिंग संकेत हैं। ईमेल लिंक नहीं, आधिकारिक साइट उपयोग करें।",kn:"ನಕಲಿ ಡೊಮೇನ್ ಮತ್ತು ತುರ್ತು ಫಿಷಿಂಗ್ ಸಂಕೇತಗಳು. ಇಮೇಲ್ ಲಿಂಕ್ ಅಲ್ಲ, ಅಧಿಕೃತ ಸೈಟ್ ಬಳಸಿ."}}
  ];
  let quizAns = Array(QUIZ.length).fill(null);
  function renderQuiz(){
    const c=$("quiz-container"); clearChildren(c);
    let score=0;
    QUIZ.forEach((q,qi)=>{
      const box=document.createElement("div"); box.className="quiz-q";
      const h=document.createElement("h3"); h.textContent=(qi+1)+". "+(q.q[lang]||q.q.en); box.appendChild(h);
      const opts=document.createElement("div"); opts.className="quiz-options";
      (q.opts[lang]||q.opts.en).forEach((opt,oi)=>{
        const lab=document.createElement("label"); lab.className="quiz-opt";
        const inp=document.createElement("input"); inp.type="radio"; inp.name="q"+qi; inp.checked=quizAns[qi]===oi;
        inp.addEventListener("change", ()=>{ quizAns[qi]=oi; renderQuiz(); });
        lab.appendChild(inp);
        const sp=document.createElement("span"); sp.textContent=opt; lab.appendChild(sp);
        if(quizAns[qi]!==null){
          if(oi===q.a) lab.classList.add("correct");
          if(quizAns[qi]===oi && oi!==q.a) lab.classList.add("wrong");
        }
        opts.appendChild(lab);
      });
      box.appendChild(opts);
      if(quizAns[qi]!==null){
        const exp=document.createElement("p"); exp.className="quiz-exp"; exp.textContent=(quizAns[qi]===q.a?"✓ ":"")+(q.exp[lang]||q.exp.en); box.appendChild(exp);
        if(quizAns[qi]===q.a) score++;
      }
      c.appendChild(box);
    });
    $("quiz-score").textContent=score+"/"+QUIZ.length;
  }
  $("quiz-reset").addEventListener("click", ()=>{ quizAns=Array(QUIZ.length).fill(null); renderQuiz(); });

  // Init
  initTheme();
  $("lang-select").value=lang;
  $("history-consent").checked=hasConsent();
  applyI18n();
  renderHistory();
  updatePw();
  renderQuiz();
})();
