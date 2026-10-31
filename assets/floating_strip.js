/* ═══ Aegis Floating Progress Strip v6 ═══
   Bottom-docked — does NOT cover the page header.
   Uses !important + max z-index for guaranteed visibility */
(function(){
  'use strict';
  var ID='aegis-floating-strip', MS=500;

  /* Inject CSS — BOTTOM docked */
  var css=document.createElement('style');
  css.textContent=
    '#'+ID+'{'+
      'position:fixed !important;'+
      'bottom:0 !important;'+
      'top:auto !important;'+
      'left:0 !important;'+
      'right:0 !important;'+
      'z-index:2147483647 !important;'+
      'display:none;'+
      'align-items:center;'+
      'gap:14px;'+
      'padding:8px 24px;'+
      'font-family:"JetBrains Mono",Consolas,monospace;'+
      'background:linear-gradient(90deg,#060c12 0%,#08101a 50%,#060c12 100%) !important;'+
      'border-top:2px solid rgba(0,200,140,0.4) !important;'+
      'border-bottom:none !important;'+
      'box-shadow:0 -4px 30px rgba(0,200,140,0.2) !important;'+
      'backdrop-filter:blur(16px);'+
      'pointer-events:none;'+
      'transition:opacity 0.3s ease;'+
    '}'+
    '#'+ID+'.afp-show{display:flex !important;}'+
    '#'+ID+' .afp-pulse{animation:afp-glow 2s ease-in-out infinite;}'+
    '@keyframes afp-glow{0%,100%{opacity:1;}50%{opacity:0.5;}}';
  document.head.appendChild(css);

  function mk(){
    var e=document.getElementById(ID);
    if(e) return e;
    e=document.createElement('div'); e.id=ID;
    e.innerHTML=
      '<span class="afp-pulse" style="font-size:14px;margin-right:8px">📡</span>'+
      '<span id="afp-phase" style="color:#00c88c;font-size:12px;font-weight:900;letter-spacing:1px;margin-right:18px">SCANNING</span>'+
      '<span style="color:#3a5060;font-size:8px;font-weight:700;letter-spacing:1.5px;margin-right:4px">TOOL</span>'+
      '<span id="afp-tool" style="color:#00e5ff;font-size:12px;font-weight:900;margin-right:14px">—</span>'+
      '<span id="afp-pct" style="color:#ffd700;font-size:12px;font-weight:900;margin-right:18px">0%</span>'+
      '<span style="flex:1"></span>'+
      '<div style="width:240px;height:6px;background:#1a2030;border-radius:4px;overflow:hidden">'+
        '<div id="afp-bar" style="width:0%;height:100%;border-radius:4px;background:linear-gradient(90deg,#00c88c,#00e5ff);transition:width 0.6s ease"></div>'+
      '</div>';
    document.body.appendChild(e);
    console.log('[Aegis] Floating progress strip v6 created — bottom docked');
    return e;
  }

  function sync(){
    var bar=mk(), isRunning=false;

    /* Method 1: progress bar value */
    var pb=document.getElementById('ext-pentest-progress-bar');
    var pctNum=0;
    if(pb){
      pctNum=parseInt(pb.getAttribute('aria-valuenow'))||0;
      if(pctNum>0 && pctNum<100) isRunning=true;
    }

    /* Method 2: status bar text */
    var sb=document.getElementById('ext-status-bar');
    if(sb){
      var sbt=sb.textContent.toLowerCase();
      if(sbt.indexOf('scanning')>=0||sbt.indexOf('running')>=0) isRunning=true;
    }

    /* Method 3: Activity Monitor phase */
    var amP=document.getElementById('ext-am-phase');
    if(amP){
      var pt=amP.textContent.toLowerCase();
      if(pt.indexOf('recon')>=0||pt.indexOf('vuln')>=0||
         pt.indexOf('exploit')>=0||pt.indexOf('post')>=0||
         pt.indexOf('scan')>=0) isRunning=true;
    }

    /* Show/hide */
    if(isRunning){ bar.classList.add('afp-show'); }
    else{ bar.classList.remove('afp-show'); return; }

    /* Update text */
    var d;
    d=document.getElementById('afp-phase');
    if(d && amP) d.textContent=amP.textContent||'SCANNING';

    var amT=document.getElementById('ext-am-tool');
    d=document.getElementById('afp-tool');
    if(d && amT) d.textContent=amT.textContent||'—';

    var amPct=document.getElementById('ext-am-pct');
    d=document.getElementById('afp-pct');
    if(d){ d.textContent=(amPct&&amPct.textContent)?amPct.textContent:pctNum+'%'; }

    d=document.getElementById('afp-bar');
    if(d) d.style.width=pctNum+'%';
  }

  /* Start polling after a delay to let Dash mount */
  setTimeout(function(){ setInterval(sync,MS); },2000);

  /* Auto-scroll to log panel when scan starts */
  var wasRunning = false;
  setInterval(function(){
    var sb = document.getElementById('ext-status-bar');
    if(!sb) return;
    var txt = sb.textContent.toLowerCase();
    var nowRunning = txt.indexOf('scanning')>=0 || txt.indexOf('running')>=0;
    if(nowRunning && !wasRunning){
      var lp = document.getElementById('ext-log-panel');
      if(lp) lp.scrollIntoView({behavior:'smooth', block:'center'});
    }
    wasRunning = nowRunning;
  }, 1000);
})();
