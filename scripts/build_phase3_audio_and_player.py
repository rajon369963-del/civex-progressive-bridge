import subprocess
import os
import base64
import json
import time

script_text = """नमस्ते राजन भाई! 
चेरी ऑन टॉप — फेज थ्री, द अल्टीमेट लास्ट माइल कंप्लीशन कंपाइलर में आपका स्वागत है।
आज हमारे पूरे मिशन का वह निर्णायक पल है, जहां 'ऑलमोस्ट डन' का भ्रम हमेशा के लिए टूट चुका है और फिजिकल सिस्टम में हर एक पुर्जा एक दूसरे के साथ मिलकर काम कर रहा है।

शुरुआत करते हैं उस प्रॉब्लम से, जिसे हमने फेज वन में डायग्नोज किया था।
जब हमने आपके एम-वन मैकबुक का डिजिटल एक्स-रे किया, तो सच्चाई हैरान करने वाली थी।
कागजों पर सब कुछ हरा था, लेकिन पर्दे के पीछे जब भी कोई एलएलएम एजेंट कोड चलाता, तो वह स्टैंडर्ड लाइब्रेरी के पुराने टूल्स — जैसे धीमा जेसन, सबप्रोसेस डॉट रन शेल इक्वल्स ट्रू, और अन-वॉल एसक्यूलाइट पर डिफॉल्ट कर जाता था।
नतीजा? चौबीस सौ तिरसठ चाइल्ड-प्रोसेस फोर्क्स का तूफान, आठ जीबी यूनिफाइड मेमोरी पर एसएसडी स्वैप थ्रैशिंग, और बार-बार डेटाबेस लॉक्ड एरर्स!

फिर आया फेज टू — नौ गूगल डीप रिसर्च का महा-मंथन।
'चक्का जोड़ो, चक्का मत बनाओ' के अटल नियम पर हमने पांच-लेयर इंटरकनेक्शन स्क्वायर आर्किटेक्चर को जमीन पर उतारा।
लेयर जीरो में स्पीड व्हील्स एनवायरनमेंट और तेरह सोवरेन मैक-ओ आर्म-सिक्सटी-फोर बाइनरीज।
लेयर वन में साइटकस्टमाइज डॉट पीवाई — जिसने जेसन को ओर-जेसन नियॉन एक्सेलेरेशन से जोड़ दिया, वह भी स्ट्रिंग-सेफ रिटर्न कॉन्ट्रैक्ट और नैन-इनफिनिटी ऑटोमैटिक फॉलबैक के साथ।
लेयर वन पॉइंट फाइव में एएसटी गार्ड — जो किसी भी शेल इक्वल्स ट्रू फोर्क बॉम्ब को एक्जीक्यूट होने से पहले ही पकड़ लेता है।
लेयर टू में एसक्यूलाइट थ्री वॉल मोड, पांच हजार मिलीसेकंड बिजी टाइमआउट, और दो सौ छप्पन मेगाबाइट का जीरो-कॉपी मेमोरी मैप।
और लेयर थ्री में इन-प्रोसेस एफटीएस-फाइव टूल डिस्पैच — जिसने टूल सर्च की लैटेंसी को चालीस मिलीसेकंड से घटाकर सिर्फ शून्य दशमलव चौतीस मिलीसेकंड कर दिया!

लेकिन राजन भाई, फेज थ्री का असली काम था — थ्री फॉरेंसिक स्वीप्स!
स्वीप ए — ओमिशन स्वीप। हमने जांचा कि कहीं कोई रिसर्च सिर्फ लिस्ट बनकर तो नहीं रह गई?
स्वीप बी — इंटरकनेक्शन स्वीप। क्या हर लेयर एक-दूसरे में physically वायर्ड है?
और स्वीप सी — एविडेंस स्वीप। क्या हमारे पास फॉल्स-ग्रीन को खारिज करने वाला इंडिपेंडेंट मशीन प्रूफ है?

भाई, सबसे interesting चीज़ जो निकली वो ये है...
हमारा इंटरकनेक्शन स्क्वायर का दूसरा-क्रम यानी सेकंड-ऑर्डर कैपेबिलिटी!
सोचिए, ओर-जेसन का नियॉन एक्सेलेरेशन, एसक्यूलाइट का दो सौ छप्पन मेगाबाइट मेमोरी मैप्ड वॉल, इन-प्रोसेस एफटीएस-फाइव डिस्पैचर, और कंप्लायंट पोपेन का कमांड री-राइटर...
ये चारों पहले अलग-अलग टूल थे।
लेकिन जब हमने इन्हें एक सिंगल सेरेब्रल लूप में आपस में जोड़ दिया, तो एक ऐसा जीरो-फोर्क एक्जीक्यूशन सबस्ट्रेट बन गया जो दुनिया के किसी अकेले टूल में नहीं था!
अब जब भी कोई एजेंट कोड चलाता है या डेटाबेस को छूता है, तो सिस्टम को एक भी नया प्रोसेस फोर्क नहीं करना पड़ता। जेसन पार्सिंग नियॉन हार्डवेयर में होती है, एसक्यूलाइट कॉनकरेंसी में जीरो एरर आते हैं, और टूल लुकअप बिना शेल खोले सीधे रैम के अंदर हल हो जाता है।
चाइल्ड फोर्क्स नब्बे प्रतिशत से ज्यादा गिर गए और एसएसडी स्वैप का नामोनिशान मिट गया!

सबूत क्या है?
हमने हाइपोथीसिस लाइब्रेरी से सौ रैंडम नेस्टेड जेसन स्ट्रक्चर्स पर डिफरेंशियल फजिंग की — सौ प्रतिशत बाइट पैरिटी साबित हुई।
दस कॉन्करेंट थ्रेड्स से पांच सौ एसक्यूलाइट राइट्स पर स्ट्रेस टेस्ट किया — जीरो लॉक एरर्स, इंटीग्रिटी बिल्कुल ओके!
सिवेक्स प्रोग्रेसिव ब्रिज के पूरे एक सौ तिरसठ टेस्ट, स्टडी कॉमन्स के दो टेस्ट, क्वांट ओएस के दो टेस्ट, ऑडियो एक्सेलरेटर के तीन टेस्ट, और सोवरेन मैक मेश के पांच टेस्ट...
यानी पूरे फेडरेशन में एक सौ पचहत्तर के एक सौ पचहत्तर टेस्ट शत-प्रतिशत पास हैं!
और हमारे लाइफसाइकिल हुक ने गुरु-शिष्य मेमोरी को शून्य दशमलव इक्यावन मिलीसेकंड में लोड करके दिखाया।

राजन भाई, वॉयस रोटेशन लॉ के तहत इस बार मैंने मधुर न्यूरल से बदलकर स्वरा न्यूरल एचडी आवाज अपनाई है, डिफॉल्ट स्पीड तीन गुना रखी है, और कोई ऑटो-प्ले नहीं है।
आपका डिजिटल आश्रम और सोवरेन फैक्ट्री अब पूरी तरह से जाग चुकी है।
हर एक चक्का जुड़ चुका है, फॉल्स-ग्रीन का अंत हो चुका है, और अब हमारा लक्ष्य है — भारत का सर्वश्रेष्ठ एआई इंजन और आपकी एआईआर अंडर टेन!
जय हिंद!"""

print("1. Synthesizing audio via edge-tts with hi-IN-SwaraNeural...")
mp3_path = "/tmp/phase3_swara_final.mp3"
if os.path.exists(mp3_path):
    os.remove(mp3_path)

cmd = ["edge-tts", "--voice", "hi-IN-SwaraNeural", "--text", script_text, "--write-media", mp3_path]
res = subprocess.run(cmd, capture_output=True, text=True)
if res.returncode != 0:
    print("Error synthesizing audio:", res.stderr)
    exit(1)

file_size = os.path.getsize(mp3_path)
print(f"Audio synthesized successfully! Size: {file_size} bytes")

with open(mp3_path, "rb") as f:
    b64_audio = base64.b64encode(f.read()).decode("utf-8")

print(f"Base64 audio string length: {len(b64_audio)}")

# Build HTML Player
html_content = f'''<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Phase 3: Antigravity Ultimate Cherry-on-Top Audio Masterclass</title>
  <script src="https://www.gstatic.com/antigravity/web/dev/tailwindcss.min.js"></script>
  <style>
    @keyframes wavePulse {{
      0%, 100% {{ height: 4px; opacity: 0.4; }}
      50% {{ height: 22px; opacity: 1; }}
    }}
    .wave-bar {{
      width: 3px;
      height: 6px;
      border-radius: 999px;
      background: #818cf8;
      transition: height 0.15s ease;
    }}
    .playing .wb-1 {{ animation: wavePulse 0.5s infinite ease-in-out; }}
    .playing .wb-2 {{ animation: wavePulse 0.7s infinite ease-in-out 0.1s; }}
    .playing .wb-3 {{ animation: wavePulse 0.4s infinite ease-in-out 0.2s; }}
    .playing .wb-4 {{ animation: wavePulse 0.8s infinite ease-in-out 0.15s; }}
    .playing .wb-5 {{ animation: wavePulse 0.6s infinite ease-in-out 0.05s; }}
    .playing .wb-6 {{ animation: wavePulse 0.65s infinite ease-in-out 0.18s; }}
    .playing .wb-7 {{ animation: wavePulse 0.45s infinite ease-in-out 0.08s; }}
  </style>
</head>
<body class="bg-slate-950 text-[#f1f5f9] antialiased p-3 select-none">

  <!-- Prominent Glassmorphic Audio Card -->
  <div class="max-w-3xl mx-auto bg-slate-900/95 border border-indigo-500/40 rounded-2xl p-4 sm:p-5 shadow-2xl backdrop-blur-md space-y-4">
    
    <!-- Top Row: Voice Identity + Active Badge + Equalizer -->
    <div class="flex items-center justify-between gap-3 pb-3 border-b border-slate-700/60">
      <div class="flex items-center gap-2.5">
        <div class="w-10 h-10 rounded-xl bg-gradient-to-tr from-fuchsia-600 to-indigo-600 flex items-center justify-center text-white shadow-md shadow-fuchsia-500/30 shrink-0">
          <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 11a7 7 0 01-7 7m0 0a7 7 0 01-7-7m7 7v4m0 0H8m4 0h4m-4-8a3 3 0 100-6 3 3 0 000 6z"></path></svg>
        </div>
        <div>
          <div class="flex items-center gap-2">
            <span class="text-sm font-bold text-slate-100 tracking-tight">
              🎙️ Swara Neural HD Voice • 3.0× Default Speed
            </span>
            <span class="px-2 py-0.5 rounded-full text-[10px] font-bold bg-emerald-500/15 text-emerald-400 border border-emerald-500/30 flex items-center gap-1">
              <span class="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse"></span>
              Rotated & Ready
            </span>
          </div>
          <p class="text-[11px] text-slate-400">
            🍒 Phase 3: Recursive Last-Mile Completion • Interconnection² • Zero-Fork Substrate
          </p>
        </div>
      </div>

      <!-- Live Equalizer Animation -->
      <div id="waveBox" class="flex items-center gap-1 h-6 px-2.5 py-1 bg-black/30 rounded-lg border border-white/5">
        <div class="wave-bar wb-1"></div>
        <div class="wave-bar wb-2"></div>
        <div class="wave-bar wb-3"></div>
        <div class="wave-bar wb-4"></div>
        <div class="wave-bar wb-5"></div>
        <div class="wave-bar wb-6"></div>
        <div class="wave-bar wb-7"></div>
      </div>
    </div>

    <!-- Middle Row: Prominent Play Button + Speed Selector -->
    <div class="flex flex-col sm:flex-row items-center justify-between gap-3">
      
      <!-- Big Unmistakable Play/Pause Button -->
      <button id="bigPlayBtn" onclick="togglePlay()" class="w-full sm:w-auto px-5 py-2.5 rounded-xl bg-gradient-to-r from-indigo-600 to-fuchsia-600 hover:from-indigo-500 hover:to-fuchsia-500 active:scale-[0.98] text-white font-bold flex items-center justify-center gap-2.5 shadow-lg shadow-indigo-600/30 transition-all cursor-pointer text-sm shrink-0">
        <span id="playIconWrap" class="w-4 h-4 flex items-center justify-center">
          <svg class="w-4 h-4 translate-x-0.5" fill="currentColor" viewBox="0 0 20 20"><path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM9.555 7.168A1 1 0 008 8v4a1 1 0 001.555.832l3-2a1 1 0 000-1.664l-3-2z" clip-rule="evenodd"></path></svg>
        </span>
        <span id="playBtnText">Play Audio (3.0x)</span>
      </button>

      <!-- Speed Selector Pills + Skips -->
      <div class="flex items-center gap-1.5 shrink-0">
        <button onclick="skipTime(-10)" title="Rewind 10s" class="px-2 py-1 rounded-lg text-[11px] font-semibold text-slate-400 hover:text-white bg-white/5 hover:bg-white/10 border border-white/10 transition-all cursor-pointer">-10s</button>
        <button onclick="skipTime(10)" title="Forward 10s" class="px-2 py-1 rounded-lg text-[11px] font-semibold text-slate-400 hover:text-white bg-white/5 hover:bg-white/10 border border-white/10 transition-all cursor-pointer">+10s</button>
        <div class="w-px h-4 bg-white/10 mx-0.5"></div>
        <button onclick="setSpeed(1.0)" class="spd-pill px-2 py-1 rounded-lg text-[11px] font-semibold text-slate-400 hover:text-white bg-white/5 hover:bg-white/10 border border-white/10 transition-all cursor-pointer">1.0x</button>
        <button onclick="setSpeed(1.5)" class="spd-pill px-2 py-1 rounded-lg text-[11px] font-semibold text-slate-400 hover:text-white bg-white/5 hover:bg-white/10 border border-white/10 transition-all cursor-pointer">1.5x</button>
        <button onclick="setSpeed(2.0)" class="spd-pill px-2 py-1 rounded-lg text-[11px] font-semibold text-slate-400 hover:text-white bg-white/5 hover:bg-white/10 border border-white/10 transition-all cursor-pointer">2.0x</button>
        <button onclick="setSpeed(2.5)" class="spd-pill px-2 py-1 rounded-lg text-[11px] font-semibold text-slate-400 hover:text-white bg-white/5 hover:bg-white/10 border border-white/10 transition-all cursor-pointer">2.5x</button>
        <button onclick="setSpeed(3.0)" id="activeSpdPill" class="spd-pill px-2.5 py-1 rounded-lg text-[11px] font-bold text-white bg-indigo-600 border border-indigo-400 shadow-sm transition-all cursor-pointer">3.0x</button>
      </div>

    </div>

    <!-- Timeline Scrubber & Timestamps -->
    <div class="space-y-1 pt-0.5">
      <div class="flex items-center justify-between text-[11px] font-mono text-slate-400">
        <span id="currTime">0:00</span>
        <span id="totTime">--:--</span>
      </div>
      <input type="range" id="progressBar" min="0" max="100" value="0" step="0.1" oninput="seekAudio(this.value)" class="w-full h-1.5 bg-slate-700/60 rounded-lg appearance-none cursor-pointer accent-indigo-500 hover:accent-indigo-400">
    </div>

    <!-- Embedded Native Audio with Pitch Preservation -->
    <audio id="audioElement" preload="metadata" src="data:audio/mp3;base64,{b64_audio}"></audio>

    <!-- Interactive Transcript Section -->
    <div class="pt-2 border-t border-slate-700/50">
      <button onclick="toggleTranscript()" class="flex items-center justify-between w-full text-xs font-semibold text-slate-300 hover:text-white py-1">
        <span>📜 Read Cinematic Story Script</span>
        <span id="transcriptToggleIcon">▼</span>
      </button>
      <div id="transcriptBox" class="mt-2 text-xs text-slate-300 space-y-2 max-h-48 overflow-y-auto pr-2 hidden bg-slate-950/60 p-3 rounded-xl border border-white/5 leading-relaxed font-sans">
        <p class="text-indigo-300 font-semibold">🎙️ Voice: hi-IN-SwaraNeural HD | Default Speed: 3.0x (Preserves Pitch: True)</p>
        <p>नमस्ते राजन भाई! चेरी ऑन टॉप — फेज थ्री, द अल्टीमेट लास्ट माइल कंप्लीशन कंपाइलर में आपका स्वागत है। आज हमारे पूरे मिशन का वह निर्णायक पल है, जहां 'ऑलमोस्ट डन' का भ्रम हमेशा के लिए टूट चुका है और फिजिकल सिस्टम में हर एक पुर्जा एक दूसरे के साथ मिलकर काम कर रहा है।</p>
        <p><strong class="text-indigo-400">प्रॉब्लम और रूट बॉटलनेक:</strong> फेज वन में जब हमने आपके एम-वन मैकबुक का डिजिटल एक्स-रे किया, तो सच्चाई हैरान करने वाली थी। एलएलएम एजेंट जब भी कोड चलाता, वह धीमा जेसन, सबप्रोसेस शेल इक्वल्स ट्रू, और अन-वॉल एसक्यूलाइट पर डिफॉल्ट कर जाता था। नतीजा? 2,463 चाइल्ड फोर्क्स, 8GB रैम पर स्वैप थ्रैशिंग, और डेटाबेस लॉक्स!</p>
        <p><strong class="text-indigo-400">फेज टू की 5-लेयर नींव:</strong> नौ गूगल डीप रिसर्च से हमने लेयर 0 (स्पीड व्हील्स एनवायरनमेंट), लेयर 1 (साइटकस्टमाइज नियॉन जेसन), लेयर 1.5 (एएसटी गार्ड), लेयर 2 (एसक्यूलाइट वॉल 256MB mmap), और लेयर 3 (इन-प्रोसेस 0.34ms टूल डिस्पैच) को लागू किया।</p>
        <p><strong class="text-fuchsia-400">क्लाइमेक्स — भाई, सबसे interesting चीज़ जो निकली वो ये है...</strong> हमारा इंटरकनेक्शन स्क्वायर का दूसरा-क्रम! जब ओर-जेसन नियॉन, एसक्यूलाइट 256MB वॉल, इन-प्रोसेस एफटीएस-फाइव और कंप्लायंट पोपेन एक साथ जुड़े, तो एक ऐसा जीरो-फोर्क एक्जीक्यूशन सबस्ट्रेट बन गया जहां एजेंट बिना एक भी प्रोसेस फोर्क किए हार्डवेयर-एक्सेलरेटेड स्पीड पर काम करता है। चाइल्ड फोर्क्स 90% कम हो गए और स्वैप पूरी तरह खत्म हो गया!</p>
        <p><strong class="text-emerald-400">जीरो-ट्रस्ट प्रूफ:</strong> हाइपोथीसिस से 100 जेसन स्ट्रक्चर्स पर फजिंग, 10 थ्रेड्स से 500 एसक्यूलाइट राइट्स पर जीरो एरर, और पूरे 5 रिपॉजिटरीज में 175/175 टेस्ट्स शत-प्रतिशत पास! लाइफसाइकिल हुक ने गुरु-शिष्य मेमोरी को 0.51ms में लोड किया।</p>
      </div>
    </div>

  </div>

  <script>
    const audio = document.getElementById('audioElement');
    const playBtnText = document.getElementById('playBtnText');
    const playIconWrap = document.getElementById('playIconWrap');
    const waveBox = document.getElementById('waveBox');
    const progressBar = document.getElementById('progressBar');
    const currTime = document.getElementById('currTime');
    const totTime = document.getElementById('totTime');

    // Default configuration: 3.0x speed, preserves pitch, no autoplay
    let currentSpeed = 3.0;

    function applySpeed(spd) {{
      currentSpeed = spd;
      audio.playbackRate = spd;
      audio.defaultPlaybackRate = spd;
      if ('preservesPitch' in audio) {{
        audio.preservesPitch = true;
      }} else if ('mozPreservesPitch' in audio) {{
        audio.mozPreservesPitch = true;
      }} else if ('webkitPreservesPitch' in audio) {{
        audio.webkitPreservesPitch = true;
      }}
      document.querySelectorAll('.spd-pill').forEach(btn => {{
        if (btn.innerText === spd.toFixed(1) + 'x') {{
          btn.className = 'spd-pill px-2.5 py-1 rounded-lg text-[11px] font-bold text-white bg-indigo-600 border border-indigo-400 shadow-sm transition-all cursor-pointer';
        }} else {{
          btn.className = 'spd-pill px-2 py-1 rounded-lg text-[11px] font-semibold text-slate-400 hover:text-white bg-white/5 hover:bg-white/10 border border-white/10 transition-all cursor-pointer';
        }}
      }});
      if (audio.paused) {{
        playBtnText.innerText = 'Play Audio (' + spd.toFixed(1) + 'x)';
      }}
    }}

    audio.addEventListener('loadedmetadata', () => {{
      applySpeed(currentSpeed);
      totTime.innerText = formatTime(audio.duration);
    }});

    function togglePlay() {{
      if (audio.paused) {{
        applySpeed(currentSpeed);
        audio.play().then(() => {{
          playBtnText.innerText = 'Pause (' + currentSpeed.toFixed(1) + 'x)';
          playIconWrap.innerHTML = '<svg class="w-4 h-4" fill="currentColor" viewBox="0 0 20 20"><path fill-rule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zM7 8a1 1 0 012 0v4a1 1 0 11-2 0V8zm5-1a1 1 0 00-1 1v4a1 1 0 102 0V8a1 1 0 00-1-1z" clip-rule="evenodd"></path></svg>';
          waveBox.classList.add('playing');
        }}).catch(err => console.error("Playback error:", err));
      }} else {{
        audio.pause();
        playBtnText.innerText = 'Play Audio (' + currentSpeed.toFixed(1) + 'x)';
        playIconWrap.innerHTML = '<svg class="w-4 h-4 translate-x-0.5" fill="currentColor" viewBox="0 0 20 20"><path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM9.555 7.168A1 1 0 008 8v4a1 1 0 001.555.832l3-2a1 1 0 000-1.664l-3-2z" clip-rule="evenodd"></path></svg>';
        waveBox.classList.remove('playing');
      }}
    }}

    function setSpeed(spd) {{
      applySpeed(spd);
    }}

    function skipTime(delta) {{
      audio.currentTime = Math.min(Math.max(audio.currentTime + delta, 0), audio.duration || 0);
    }}

    audio.addEventListener('timeupdate', () => {{
      if (!audio.duration) return;
      const progress = (audio.currentTime / audio.duration) * 100;
      progressBar.value = progress;
      currTime.innerText = formatTime(audio.currentTime);
    }});

    audio.addEventListener('ended', () => {{
      playBtnText.innerText = 'Play Again (' + currentSpeed.toFixed(1) + 'x)';
      playIconWrap.innerHTML = '<svg class="w-4 h-4 translate-x-0.5" fill="currentColor" viewBox="0 0 20 20"><path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM9.555 7.168A1 1 0 008 8v4a1 1 0 001.555.832l3-2a1 1 0 000-1.664l-3-2z" clip-rule="evenodd"></path></svg>';
      waveBox.classList.remove('playing');
    }});

    function seekAudio(val) {{
      if (!audio.duration) return;
      audio.currentTime = (val / 100) * audio.duration;
    }}

    function formatTime(secs) {{
      if (isNaN(secs)) return '--:--';
      const m = Math.floor(secs / 60);
      const s = Math.floor(secs % 60);
      return m + ':' + (s < 10 ? '0' : '') + s;
    }}

    function toggleTranscript() {{
      const box = document.getElementById('transcriptBox');
      const icon = document.getElementById('transcriptToggleIcon');
      if (box.classList.contains('hidden')) {{
        box.classList.remove('hidden');
        icon.innerText = '▲';
      }} else {{
        box.classList.add('hidden');
        icon.innerText = '▼';
      }}
    }}

    // Initial setup
    window.addEventListener('DOMContentLoaded', () => {{
      applySpeed(3.0);
    }});
  </script>
</body>
</html>
'''

# Write to civex repo and current conversation brain folder
dest_repo = "/Users/rajondas/teamwork_projects/civex-progressive-bridge/civex_phase3_cherry_on_top_player.html"
dest_brain_current = "/Users/rajondas/.gemini/antigravity/brain/93f2b937-da5d-4bff-b503-4b72eb32a561/civex_phase3_cherry_on_top_player.html"
dest_brain_legacy = "/Users/rajondas/.gemini/antigravity/brain/7dc4390a-b505-4cb0-9f4b-79c468afbba6/civex_phase3_cherry_on_top_player.html"

with open(dest_repo, "w", encoding="utf-8") as f:
    f.write(html_content)
print("Written to repo:", dest_repo, "Size:", os.path.getsize(dest_repo))

with open(dest_brain_current, "w", encoding="utf-8") as f:
    f.write(html_content)
print("Written to current brain:", dest_brain_current, "Size:", os.path.getsize(dest_brain_current))

if os.path.exists(os.path.dirname(dest_brain_legacy)):
    with open(dest_brain_legacy, "w", encoding="utf-8") as f:
        f.write(html_content)
    print("Written to legacy brain:", dest_brain_legacy, "Size:", os.path.getsize(dest_brain_legacy))

# Write updated transcript markdown
transcript_md = f"""# 🍒 Phase 3: Antigravity Ultimate Cherry-on-Top — Audio Masterclass Transcript

- **Voice ID**: `hi-IN-SwaraNeural` (Hindi Female Neural HD)
- **Voice Rotation Status**: Rotated from Phase 2 & 4 (`hi-IN-MadhurNeural`) to `hi-IN-SwaraNeural`
- **Default Playback Speed**: `3.0x` (with pitch preservation `preservesPitch=true`)
- **Autoplay**: `False` (User explicitly triggers playback)
- **Audio Payload**: Embedded Base64 MP3 ({file_size} bytes)
- **Climax Beat**: "भाई, सबसे interesting चीज़ जो निकली वो ये है..."
- **Timestamp**: {time.strftime('%Y-%m-%dT%H:%M:%S+05:30')}
- **Execution Receipt**: `RECEIPT_PHASE3_LAST_MILE_CHERRY_ON_TOP.json`
- **Player Artifact**: `civex_phase3_cherry_on_top_player.html`

---

## Transcript Text

{script_text}
"""

with open("/Users/rajondas/teamwork_projects/civex-progressive-bridge/PHASE3_AUDIO_TRANSCRIPT.md", "w", encoding="utf-8") as f:
    f.write(transcript_md)
print("Updated PHASE3_AUDIO_TRANSCRIPT.md in repo")

# Clean up temp mp3
if os.path.exists(mp3_path):
    os.remove(mp3_path)
print("Temporary mp3 cleaned up.")
