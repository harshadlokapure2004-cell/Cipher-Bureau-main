(function(){
"use strict";

/* ============================================================
   STORAGE — prefers the artifact's persistent window.storage,
   falls back to localStorage when running as a plain static
   site (e.g. hosted on GitHub Pages).
   ============================================================ */
async function storeGet(key){
  if (window.storage && typeof window.storage.get === 'function'){
    try { const r = await window.storage.get(key); return r ? r.value : null; }
    catch(e){ /* fall through */ }
  }
  try { return localStorage.getItem(key); } catch(e){ return null; }
}
async function storeSet(key, value){
  if (window.storage && typeof window.storage.set === 'function'){
    try { await window.storage.set(key, value); return true; }
    catch(e){ /* fall through */ }
  }
  try { localStorage.setItem(key, value); return true; } catch(e){ return false; }
}
async function storeDelete(key){
  if (window.storage && typeof window.storage.delete === 'function'){
    try { await window.storage.delete(key); return true; } catch(e){ /* fall through */ }
  }
  try { localStorage.removeItem(key); return true; } catch(e){ return false; }
}

async function sha256(text){
  const enc = new TextEncoder().encode(text);
  const buf = await crypto.subtle.digest('SHA-256', enc);
  return Array.from(new Uint8Array(buf)).map(b=>b.toString(16).padStart(2,'0')).join('');
}

/* ============================================================
   CIPHER ENGINE — verified round-trip correct.
   ============================================================ */
function mod(n, m){ return ((n % m) + m) % m; }

const Cipher = {
  caesar(text, key, decrypt){
    const k = decrypt ? mod(26 - mod(key,26), 26) : mod(key,26);
    return text.replace(/[a-zA-Z]/g, c=>{
      const base = c === c.toUpperCase() ? 65 : 97;
      return String.fromCharCode(mod(c.charCodeAt(0)-base+k,26)+base);
    });
  },
  mono(text, key, decrypt){
    key = key.toUpperCase();
    const map = new Array(26);
    if (!decrypt){ for(let i=0;i<26;i++) map[i]=key[i]; }
    else { for(let i=0;i<26;i++) map[key.charCodeAt(i)-65]=String.fromCharCode(65+i); }
    return text.replace(/[a-zA-Z]/g, c=>{
      const isUpper = c===c.toUpperCase();
      const idx = c.toUpperCase().charCodeAt(0)-65;
      const m2 = map[idx];
      return isUpper ? m2 : m2.toLowerCase();
    });
  },
  vigenere(text, key, decrypt){
    key = key.replace(/[^a-zA-Z]/g,'').toUpperCase();
    let ki=0;
    return text.replace(/[a-zA-Z]/g, c=>{
      const isUpper = c===c.toUpperCase();
      const base = isUpper?65:97;
      const shift = key.charCodeAt(ki%key.length)-65;
      ki++;
      const s = decrypt ? -shift : shift;
      return String.fromCharCode(mod(c.charCodeAt(0)-base+s,26)+base);
    });
  },
  otp(text, key, decrypt){
    key = key.replace(/[^a-zA-Z]/g,'').toUpperCase();
    let ki=0;
    return text.replace(/[a-zA-Z]/g, c=>{
      const isUpper = c===c.toUpperCase();
      const base = isUpper?65:97;
      const k = key.charCodeAt(ki)-65;
      ki++;
      const s = decrypt ? -k : k;
      return String.fromCharCode(mod(c.charCodeAt(0)-base+s,26)+base);
    });
  },
  railFenceEncrypt(text, rails){
    if (rails<2) return text;
    const fence = Array.from({length:rails},()=>[]);
    let rail=0, dir=1;
    for (const ch of text){
      fence[rail].push(ch);
      if (rail===0) dir=1; else if (rail===rails-1) dir=-1;
      rail+=dir;
    }
    return fence.flat().join('');
  },
  railFenceDecrypt(cipher, rails){
    if (rails<2) return cipher;
    const len = cipher.length;
    const pattern=[]; let rail=0, dir=1;
    for(let i=0;i<len;i++){
      pattern.push(rail);
      if (rail===0) dir=1; else if (rail===rails-1) dir=-1;
      rail+=dir;
    }
    const counts = new Array(rails).fill(0);
    pattern.forEach(r=>counts[r]++);
    const segments=[]; let idx=0;
    for(let r=0;r<rails;r++){ segments.push(cipher.slice(idx, idx+counts[r])); idx+=counts[r]; }
    const pos = new Array(rails).fill(0);
    let result='';
    for(let i=0;i<len;i++){ const r=pattern[i]; result+=segments[r][pos[r]++]; }
    return result;
  },
  getColumnOrder(key){
    const arr = key.toUpperCase().split('').map((ch,i)=>({ch,i}));
    const sorted = [...arr].sort((a,b)=> a.ch===b.ch ? a.i-b.i : (a.ch<b.ch?-1:1));
    return sorted.map(item=>item.i);
  },
  columnarEncrypt(text, key){
    const k = key.length;
    const numRows = Math.ceil(text.length/k);
    const numLongCols = text.length - (numRows-1)*k;
    const columns = Array.from({length:k},()=>'');
    let charIndex=0;
    for(let r=0;r<numRows;r++){
      for(let c=0;c<k;c++){
        if (c<numLongCols || r<numRows-1){
          if (charIndex<text.length) columns[c]+=text[charIndex++];
        }
      }
    }
    const colByRank = Cipher.getColumnOrder(key);
    let result='';
    for(let rank=0;rank<k;rank++) result+=columns[colByRank[rank]];
    return result;
  },
  columnarDecrypt(cipher, key){
    const k = key.length;
    const colByRank = Cipher.getColumnOrder(key);
    const numRows = Math.ceil(cipher.length/k);
    const numLongCols = cipher.length - (numRows-1)*k;
    const colLengths = new Array(k);
    for(let c=0;c<k;c++) colLengths[c] = (c<numLongCols) ? numRows : numRows-1;
    const columns = new Array(k);
    let idx=0;
    for(let rank=0;rank<k;rank++){
      const colIdx = colByRank[rank];
      const len = colLengths[colIdx];
      columns[colIdx] = cipher.slice(idx, idx+len);
      idx+=len;
    }
    let result='';
    for(let r=0;r<numRows;r++){
      for(let c=0;c<k;c++){
        if (r<colLengths[c]) result+=columns[c][r];
      }
    }
    return result;
  },
  buildPlayfairGrid(key){
    key = key.toUpperCase().replace(/J/g,'I').replace(/[^A-Z]/g,'');
    const seen = new Set(); let grid='';
    for(const ch of key){ if(!seen.has(ch)){ seen.add(ch); grid+=ch; } }
    for(let i=65;i<=90;i++){
      const ch = String.fromCharCode(i);
      if (ch==='J') continue;
      if(!seen.has(ch)){ seen.add(ch); grid+=ch; }
    }
    return grid;
  },
  pfPos(grid, ch){ const idx=grid.indexOf(ch); return [Math.floor(idx/5), idx%5]; },
  playfairDigraphs(text){
    text = text.toUpperCase().replace(/J/g,'I').replace(/[^A-Z]/g,'');
    const digraphs=[]; let i=0;
    while(i<text.length){
      let a=text[i], b;
      if (i+1<text.length){
        b=text[i+1];
        if (a===b){ b='X'; i+=1; } else { i+=2; }
      } else { b='X'; i+=1; }
      digraphs.push([a,b]);
    }
    return digraphs;
  },
  playfairEncrypt(text, key){
    const grid = Cipher.buildPlayfairGrid(key);
    const digraphs = Cipher.playfairDigraphs(text);
    let result='';
    for (const [a,b] of digraphs){
      const [r1,c1]=Cipher.pfPos(grid,a), [r2,c2]=Cipher.pfPos(grid,b);
      if (r1===r2) result+= grid[r1*5+(c1+1)%5]+grid[r2*5+(c2+1)%5];
      else if (c1===c2) result+= grid[((r1+1)%5)*5+c1]+grid[((r2+1)%5)*5+c2];
      else result+= grid[r1*5+c2]+grid[r2*5+c1];
    }
    return result;
  },
  playfairDecrypt(cipher, key){
    const grid = Cipher.buildPlayfairGrid(key);
    let result='';
    for(let i=0;i<cipher.length;i+=2){
      const a=cipher[i], b=cipher[i+1];
      if (b===undefined) break;
      const [r1,c1]=Cipher.pfPos(grid,a), [r2,c2]=Cipher.pfPos(grid,b);
      if (r1===r2) result+= grid[r1*5+(c1+4)%5]+grid[r2*5+(c2+4)%5];
      else if (c1===c2) result+= grid[((r1+4)%5)*5+c1]+grid[((r2+4)%5)*5+c2];
      else result+= grid[r1*5+c2]+grid[r2*5+c1];
    }
    return result;
  },
  keyToMatrix(key){
    const nums = (String(key).match(/-?\d+/g) || []).map(n=>mod(parseInt(n,10),26));
    return [[nums[0],nums[1]],[nums[2],nums[3]]];
  },
  det2(m){ return m[0][0]*m[1][1]-m[0][1]*m[1][0]; },
  modInverse(a, m){
    a = mod(a,m);
    for(let x=1;x<m;x++) if (mod(a*x,m)===1) return x;
    return null;
  },
  invertMatrix2(m){
    const det = mod(Cipher.det2(m), 26);
    const detInv = Cipher.modInverse(det,26);
    if (detInv===null) return null;
    const adj = [[m[1][1], -m[0][1]], [-m[1][0], m[0][0]]];
    return adj.map(row=>row.map(v=>mod(v*detInv,26)));
  },
  hillProcess(text, matrix){
    let clean = text.toUpperCase().replace(/[^A-Z]/g,'');
    if (clean.length%2!==0) clean+='X';
    let result='';
    for(let i=0;i<clean.length;i+=2){
      const v0=clean.charCodeAt(i)-65, v1=clean.charCodeAt(i+1)-65;
      const r0=mod(matrix[0][0]*v0+matrix[0][1]*v1,26);
      const r1=mod(matrix[1][0]*v0+matrix[1][1]*v1,26);
      result+=String.fromCharCode(r0+65)+String.fromCharCode(r1+65);
    }
    return result;
  }
};

/* ============================================================
   CIPHER CONFIG — UI metadata, samples, key generators
   ============================================================ */
const WORDS = ["CIPHER","BUREAU","ARCHIVE","SIGNAL","DOSSIER","ENIGMA","SHADOW","VAULT","SEXTANT","LANTERN"];
function randWord(){ return WORDS[Math.floor(Math.random()*WORDS.length)]; }
function randInt(min,max){ return Math.floor(Math.random()*(max-min+1))+min; }
function randLetters(n){ let s=''; for(let i=0;i<n;i++) s+=String.fromCharCode(65+randInt(0,25)); return s; }
function shuffleAlphabet(){
  const arr = "ABCDEFGHIJKLMNOPQRSTUVWXYZ".split('');
  for(let i=arr.length-1;i>0;i--){ const j=Math.floor(Math.random()*(i+1)); [arr[i],arr[j]]=[arr[j],arr[i]]; }
  return arr.join('');
}
function randInvertibleHillKey(){
  for (let attempt=0; attempt<500; attempt++){
    const key = `${randInt(0,25)} ${randInt(0,25)} ${randInt(0,25)} ${randInt(0,25)}`;
    const m = Cipher.keyToMatrix(key);
    if (Cipher.invertMatrix2(m)) return key;
  }
  return "3 2 4 1"; // extremely unlikely fallback path (verified invertible mod 26)
}

const CIPHERS = {
  caesar: {
    label:"Caesar", name:"Caesar Cipher",
    keyType:"number", keyLabel:"SHIFT (0–25)", keyPlaceholder:"e.g. 5", defaultKey:"5",
    hint:"Every letter moves the same number of places through the alphabet. Decrypting shifts it back the same distance.",
    sample:"ATTACK AT DAWN",
    genKey:()=>String(randInt(1,25)),
    validate:(k)=>{ const n=parseInt(k,10); if (isNaN(n)) return "The shift needs to be a whole number."; return null; },
    run:(text,key,decrypt)=>Cipher.caesar(text, parseInt(key,10)||0, decrypt)
  },
  mono: {
    label:"Monoalphabetic", name:"Monoalphabetic Cipher",
    keyType:"text", keyLabel:"CIPHER ALPHABET (26 LETTERS)", keyPlaceholder:"e.g. QWERTYUIOPASDFGHJKLZXCVBNM", defaultKey:"QWERTYUIOPASDFGHJKLZXCVBNM",
    hint:"Each of the 26 letters swaps for another, fixed by this scrambled alphabet. Position 1 of your key is what A becomes, position 2 is what B becomes, and so on.",
    sample:"MEET ME AT THE OLD BRIDGE",
    genKey:()=>shuffleAlphabet(),
    validate:(k)=>{
      const key = k.toUpperCase().replace(/[^A-Z]/g,'');
      if (key.length!==26) return "The cipher alphabet needs exactly 26 letters.";
      if (new Set(key.split('')).size!==26) return "Every letter A–Z must appear exactly once.";
      return null;
    },
    run:(text,key,decrypt)=>Cipher.mono(text, key.toUpperCase().replace(/[^A-Z]/g,''), decrypt)
  },
  playfair: {
    label:"Playfair", name:"Playfair Cipher",
    keyType:"text", keyLabel:"KEYWORD", keyPlaceholder:"e.g. BUREAU", defaultKey:"BUREAU",
    hint:"Builds a 5×5 grid from your keyword. Letters are encrypted two at a time based on where they sit in that grid.",
    sample:"THE EAGLE HAS LANDED",
    genKey:()=>randWord(),
    validate:(k)=>{ if (k.replace(/[^A-Za-z]/g,'').length<2) return "Give it a keyword of at least two letters."; return null; },
    run:(text,key,decrypt)=> decrypt ? Cipher.playfairDecrypt(text.toUpperCase().replace(/[^A-Z]/g,''), key) : Cipher.playfairEncrypt(text, key),
    caveat:"Playfair works on A–Z only: spacing, punctuation and case are dropped, J is folded into I, and a filler X is inserted for doubled letters or an odd-length message. That filler is classical Playfair's own rule, not a flaw in this tool."
  },
  hill: {
    label:"Hill", name:"Hill Cipher",
    keyType:"text", keyLabel:"KEY (4 NUMBERS 0–25 → 2×2 MATRIX)", keyPlaceholder:"e.g. 3 2 4 1", defaultKey:"3 2 4 1",
    hint:"Enter four numbers (0–25), separated by spaces or commas — they fill the 2×2 matrix left to right, top to bottom. Letters are converted to numbers and encrypted two at a time through matrix multiplication mod 26.",
    sample:"ACT NOW",
    genKey:()=>randInvertibleHillKey(),
    validate:(k)=>{
      const nums = (k.match(/-?\d+/g) || []);
      if (nums.length<4) return "The key needs 4 numbers (0–25) to form a 2×2 matrix, e.g. 3 2 4 1.";
      const m = Cipher.keyToMatrix(k);
      if (!Cipher.invertMatrix2(m)) return "That matrix has no inverse mod 26 — decryption would be impossible. Try Generate, or a different set of numbers.";
      return null;
    },
    run:(text,key,decrypt)=>{
      const m = Cipher.keyToMatrix(key);
      const useMatrix = decrypt ? Cipher.invertMatrix2(m) : m;
      return Cipher.hillProcess(text, useMatrix);
    },
    caveat:"Hill cipher works on A–Z only (spacing, punctuation and case are dropped), and pads an odd-length message with a trailing X so it splits evenly into pairs. The key is 4 numbers 0–25 (e.g. 3 2 4 1) filling the 2×2 matrix left to right, top to bottom — extra digits beyond the first 4 are ignored."
  },
  vigenere: {
    label:"Vigenère", name:"Vigenère Cipher",
    keyType:"text", keyLabel:"KEYWORD", keyPlaceholder:"e.g. SHADOW", defaultKey:"SHADOW",
    hint:"The keyword repeats across your message; each of its letters sets how far that position shifts. The same plaintext letter can become different ciphertext letters depending on where it falls.",
    sample:"THIS MESSAGE IS SECRET",
    genKey:()=>randWord(),
    validate:(k)=>{ if (k.replace(/[^A-Za-z]/g,'').length<1) return "Enter a keyword of at least one letter."; return null; },
    run:(text,key,decrypt)=>Cipher.vigenere(text, key, decrypt)
  },
  otp: {
    label:"One-Time Pad", name:"One-Time Pad",
    keyType:"text", keyLabel:"KEY (LETTERS, ≥ MESSAGE LENGTH)", keyPlaceholder:"Random letters, one per letter of your message", defaultKey:"",
    hint:"Like Vigenère, but the key never repeats — it needs at least one letter for every letter in your message. Used once with a truly random key, this is the only classical cipher that's mathematically unbreakable.",
    sample:"SEND BACKUP IMMEDIATELY",
    genKey:(currentText)=>{
      const letterCount = (currentText||'').match(/[a-zA-Z]/g)?.length || 16;
      return randLetters(Math.max(letterCount,8));
    },
    validate:(k, currentText)=>{
      const key = k.replace(/[^A-Za-z]/g,'');
      const letterCount = (currentText||'').match(/[a-zA-Z]/g)?.length || 0;
      if (key.length===0) return "Enter (or generate) a key.";
      if (key.length<letterCount) return `This key covers ${key.length} letters but the message has ${letterCount}. Generate a longer key.`;
      return null;
    },
    run:(text,key,decrypt)=>Cipher.otp(text, key, decrypt)
  },
  railfence: {
    label:"Rail Fence", name:"Rail Fence Cipher",
    keyType:"number", keyLabel:"NUMBER OF RAILS", keyPlaceholder:"e.g. 3", defaultKey:"3",
    hint:"Writes your message zigzagging down and up across this many rows, then reads each row off in turn. Every character — including spaces and punctuation — moves, and every character comes back.",
    sample:"WE ARE DISCOVERED FLEE AT ONCE",
    genKey:()=>String(randInt(2,6)),
    validate:(k)=>{ const n=parseInt(k,10); if (isNaN(n)||n<2) return "Use 2 or more rails."; return null; },
    run:(text,key,decrypt)=>{
      const rails = parseInt(key,10)||2;
      return decrypt ? Cipher.railFenceDecrypt(text, rails) : Cipher.railFenceEncrypt(text, rails);
    }
  },
  columnar: {
    label:"Columnar", name:"Columnar Transposition Cipher",
    keyType:"text", keyLabel:"KEYWORD", keyPlaceholder:"e.g. LANTERN", defaultKey:"LANTERN",
    hint:"Your message fills rows under this keyword; columns are then read off in the order the keyword's letters would sort alphabetically. Nothing is dropped — spacing and punctuation move too.",
    sample:"DEFEND THE EAST WALL AT NIGHTFALL",
    genKey:()=>randWord(),
    validate:(k)=>{ if (k.replace(/[^A-Za-z]/g,'').length<1) return "Enter a keyword of at least one letter."; return null; },
    run:(text,key,decrypt)=>{
      const cleanKey = key.replace(/[^A-Za-z]/g,'');
      return decrypt ? Cipher.columnarDecrypt(text, cleanKey) : Cipher.columnarEncrypt(text, cleanKey);
    }
  }
};
const CIPHER_ORDER = ["caesar","mono","playfair","hill","vigenere","otp","railfence","columnar"];

/* ============================================================
   ALGORITHM REFERENCE COPY
   ============================================================ */
const ALGO_COPY = [
  ["Substitution","Caesar Cipher","Shifts every letter the same fixed number of places through the alphabet. With only 25 possible shifts, it can be broken by hand in minutes — its value today is purely as the simplest possible introduction to substitution."],
  ["Substitution","Monoalphabetic Cipher","Replaces each letter with another according to a scrambled 26-letter key alphabet, rather than a simple shift. Far more key combinations than Caesar, but still vulnerable to frequency analysis since each letter always maps to the same substitute."],
  ["Digraph substitution","Playfair Cipher","Arranges a keyword into a 5×5 grid and encrypts letters two at a time, swapping each pair based on whether they share a row, a column, or neither in that grid. Invented for British diplomatic use in the 1850s, it resists simple frequency analysis better than single-letter substitution."],
  ["Polygraphic","Hill Cipher","Converts letters to numbers and encrypts them in blocks using matrix multiplication under modulo 26 arithmetic. Published in 1929, it was among the first ciphers to apply linear algebra to cryptography, and requires an invertible key matrix to be decryptable at all."],
  ["Polyalphabetic","Vigenère Cipher","Repeats a keyword across the message, with each keyword letter setting a different shift. Because identical plaintext letters can encrypt to different ciphertext letters depending on position, it defeated simple frequency analysis for roughly three centuries."],
  ["Polyalphabetic","One-Time Pad","Shifts each letter using a key at least as long as the message. When that key is truly random and used only once, this is the one classical method proven to be unbreakable — the moment a key is reused or predictable, that guarantee disappears."],
  ["Transposition","Rail Fence Cipher","Writes the message in a zigzag across a chosen number of rows, then reads each row left to right to form the ciphertext. Nothing is substituted — only reordered — which makes it fast but also relatively easy to unpick once the rail count is guessed."],
  ["Transposition","Columnar Transposition Cipher","Writes the message into rows beneath a keyword, then reads the columns back in the order the keyword's letters would sort alphabetically. Combining this with a substitution cipher was a common way to strengthen hand ciphers used well into the 20th century."]
];

/* ============================================================
   STATE
   ============================================================ */
let state = { cipher:"caesar", op:"encrypt" };

/* ============================================================
   BUILD: cipher tabs
   ============================================================ */
const cipherTabsEl = document.getElementById('cipherTabs');
CIPHER_ORDER.forEach(id=>{
  const btn = document.createElement('button');
  btn.className = 'cipher-tab' + (id===state.cipher ? ' active' : '');
  btn.textContent = CIPHERS[id].label;
  btn.dataset.cipher = id;
  btn.addEventListener('click', ()=> selectCipher(id));
  cipherTabsEl.appendChild(btn);
});

function selectCipher(id){
  state.cipher = id;
  document.querySelectorAll('.cipher-tab').forEach(b=>b.classList.toggle('active', b.dataset.cipher===id));
  const cfg = CIPHERS[id];
  document.getElementById('keyLabel').textContent = cfg.keyLabel;
  const keyInput = document.getElementById('keyInput');
  keyInput.type = cfg.keyType === 'number' ? 'text' : 'text';
  keyInput.placeholder = cfg.keyPlaceholder;
  keyInput.value = cfg.defaultKey || '';
  document.getElementById('keyHint').textContent = cfg.hint;
  const noteEl = document.getElementById('keyNote');
  if (cfg.caveat){ noteEl.style.display='block'; noteEl.textContent = cfg.caveat; }
  else { noteEl.style.display='none'; }
  clearStatus();
}
selectCipher(state.cipher);

/* Operation toggle */
document.getElementById('opToggle').addEventListener('click', (e)=>{
  const btn = e.target.closest('button');
  if (!btn) return;
  state.op = btn.dataset.op;
  document.querySelectorAll('#opToggle button').forEach(b=>b.classList.toggle('active', b===btn));
});

/* Generate key */
document.getElementById('genKeyBtn').addEventListener('click', ()=>{
  const cfg = CIPHERS[state.cipher];
  const currentText = document.getElementById('inputText').value;
  document.getElementById('keyInput').value = cfg.genKey(currentText);
  clearStatus();
});

/* Use sample */
document.getElementById('sampleBtn').addEventListener('click', ()=>{
  document.getElementById('inputText').value = CIPHERS[state.cipher].sample;
});
document.getElementById('clearBtn').addEventListener('click', ()=>{
  document.getElementById('inputText').value = '';
  document.getElementById('resultText').value = '';
  clearStatus();
  document.getElementById('stamp').classList.remove('show');
});

function showStatus(msg, type){
  const el = document.getElementById('statusMsg');
  el.textContent = msg;
  el.className = 'status-msg ' + type;
}
function clearStatus(){
  const el = document.getElementById('statusMsg');
  el.className = 'status-msg';
  el.textContent = '';
}

function runCipherOn(text, cipherId, op, key){
  const cfg = CIPHERS[cipherId];
  const err = cfg.validate ? cfg.validate(key, text) : null;
  if (err) return { error: err };
  try {
    const out = cfg.run(text, key, op === 'decrypt');
    return { result: out };
  } catch(e){
    return { error: "Something about that key or message didn't compute. Double-check the key format above." };
  }
}

/* Run */
document.getElementById('runBtn').addEventListener('click', ()=>{
  const text = document.getElementById('inputText').value;
  const key = document.getElementById('keyInput').value;
  const stampEl = document.getElementById('stamp');
  stampEl.classList.remove('show');
  if (!text){
    showStatus('Type a message first — there\'s nothing to run the cipher on yet.', 'error');
    return;
  }
  const { result, error } = runCipherOn(text, state.cipher, state.op, key);
  if (error){
    showStatus(error, 'error');
    document.getElementById('resultText').value='';
    return;
  }
  document.getElementById('resultText').value = result;
  showStatus(`${CIPHERS[state.cipher].name} · ${state.op === 'encrypt' ? 'encrypted' : 'decrypted'} successfully.`, 'ok');
  stampEl.textContent = state.op === 'encrypt' ? 'ENCRYPTED' : 'DECRYPTED';
  stampEl.classList.toggle('decrypt-stamp', state.op==='decrypt');
  void stampEl.offsetWidth;
  stampEl.classList.add('show');
});

/* Copy / download result */
document.getElementById('copyBtn').addEventListener('click', async ()=>{
  const val = document.getElementById('resultText').value;
  if (!val) return;
  try { await navigator.clipboard.writeText(val); showStatus('Result copied to clipboard.', 'ok'); }
  catch(e){ showStatus('Could not copy automatically — select the text and copy manually.', 'error'); }
});
function downloadText(filename, text){
  const blob = new Blob([text], {type:'text/plain'});
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url; a.download = filename;
  document.body.appendChild(a); a.click(); document.body.removeChild(a);
  URL.revokeObjectURL(url);
}
document.getElementById('downloadBtn').addEventListener('click', ()=>{
  const val = document.getElementById('resultText').value;
  if (!val){ showStatus('Run the cipher first — there\'s no result to save yet.', 'error'); return; }
  downloadText(`${state.cipher}-${state.op}.txt`, val);
});

/* ============================================================
   FILE ENCRYPTION / DECRYPTION
   ============================================================ */
let loadedFile = { name:null, content:null };
const fileInput = document.getElementById('fileInput');
const dropZone = document.getElementById('dropZone');
fileInput.addEventListener('change', (e)=>{
  const file = e.target.files[0];
  if (!file) return;
  const reader = new FileReader();
  reader.onload = ()=>{
    loadedFile = { name:file.name, content:reader.result };
    document.getElementById('fileMeta').textContent = `Loaded "${file.name}" — ${file.result ? '' : ''}${loadedFile.content.length.toLocaleString()} characters.`;
  };
  reader.onerror = ()=>{ document.getElementById('fileMeta').textContent = 'Could not read that file — try a plain text file.'; };
  reader.readAsText(file);
});
document.getElementById('processFileBtn').addEventListener('click', ()=>{
  if (!loadedFile.content){ document.getElementById('fileMeta').textContent = 'Choose a file first.'; return; }
  const key = document.getElementById('keyInput').value;
  const { result, error } = runCipherOn(loadedFile.content, state.cipher, state.op, key);
  if (error){ document.getElementById('fileMeta').textContent = error; return; }
  document.getElementById('fileResult').value = result;
  document.getElementById('fileMeta').textContent = `${CIPHERS[state.cipher].name} · ${state.op === 'encrypt' ? 'encrypted' : 'decrypted'} "${loadedFile.name}" using the key set in the toolkit above.`;
});
document.getElementById('downloadFileBtn').addEventListener('click', ()=>{
  const val = document.getElementById('fileResult').value;
  if (!val){ document.getElementById('fileMeta').textContent = 'Process a file first — there\'s no result to save yet.'; return; }
  const base = loadedFile.name ? loadedFile.name.replace(/\.[^.]+$/, '') : 'result';
  downloadText(`${base}-${state.op === 'encrypt' ? 'encrypted' : 'decrypted'}.txt`, val);
});

/* ============================================================
   ALGORITHM CARDS
   ============================================================ */
const algoGrid = document.getElementById('algoGrid');
ALGO_COPY.forEach(([tag, title, body])=>{
  const card = document.createElement('div');
  card.className = 'card-clip algo-card';
  card.innerHTML = `<span class="tag">${tag}</span><h3>${title}</h3><p>${body}</p>`;
  algoGrid.appendChild(card);
});

/* ============================================================
   HERO — cipher disc (SVG) + scramble line
   ============================================================ */
(function buildDisc(){
  const size=300, cx=150, cy=150;
  const outerR=132, innerR=96;
  let inner='', outer='';
  for(let i=0;i<26;i++){
    const angle = (i/26)*2*Math.PI - Math.PI/2;
    const ox = cx + outerR*Math.cos(angle), oy = cy + outerR*Math.sin(angle);
    const ix = cx + innerR*Math.cos(angle), iy = cy + innerR*Math.sin(angle);
    const letter = String.fromCharCode(65+i);
    const cipherLetter = String.fromCharCode(65+((i+7)%26));
    outer += `<text x="${ox.toFixed(1)}" y="${oy.toFixed(1)}" font-family="JetBrains Mono, monospace" font-size="11" fill="var(--ink,#eeebe4)" text-anchor="middle" dominant-baseline="middle">${letter}</text>`;
    inner += `<text x="${ix.toFixed(1)}" y="${iy.toFixed(1)}" font-family="JetBrains Mono, monospace" font-size="10" fill="var(--teal,#3ea6f0)" text-anchor="middle" dominant-baseline="middle">${cipherLetter}</text>`;
  }
  const svg = `
  <svg viewBox="0 0 300 300" xmlns="http://www.w3.org/2000/svg">
    <circle cx="150" cy="150" r="145" fill="#15141b" stroke="#39364a" stroke-width="1.5"/>
    <circle cx="150" cy="150" r="118" fill="none" stroke="#2e2b3a" stroke-width="1"/>
    <circle cx="150" cy="150" r="82" fill="none" stroke="#2e2b3a" stroke-width="1"/>
    <g class="disc-rotor">${outer}</g>
    <g>${inner}</g>
    <circle cx="150" cy="150" r="26" fill="#0c0b0f" stroke="#e0a940" stroke-width="2"/>
    <text x="150" y="156" font-family="JetBrains Mono, monospace" font-size="13" fill="#f4c869" text-anchor="middle">CB</text>
  </svg>`;
  document.getElementById('discWrap').innerHTML = svg;
})();

(function scrambleHero(){
  const el = document.getElementById('scrambleLine');
  const finalText = 'plaintext → cipher → plaintext, exactly.';
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
  const reduce = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  if (reduce){ el.textContent = finalText; return; }
  let frame = 0;
  const totalFrames = 26;
  const timer = setInterval(()=>{
    frame++;
    const revealCount = Math.floor((frame/totalFrames)*finalText.length);
    let out = '';
    for (let i=0;i<finalText.length;i++){
      if (finalText[i] === ' '){ out += ' '; continue; }
      if (i < revealCount) out += finalText[i];
      else out += chars[Math.floor(Math.random()*chars.length)];
    }
    el.textContent = out;
    if (frame>=totalFrames){ clearInterval(timer); el.textContent = finalText; }
  }, 45);
})();

document.getElementById('yearFoot').textContent = 'Runs entirely in your browser · ' + new Date().getFullYear();

/* Mobile nav toggle */
document.getElementById('navToggle').addEventListener('click', ()=>{
  document.getElementById('tabsNav').classList.toggle('open');
});

/* ============================================================
   ACCESS GATE + SECURITY PANEL
   ============================================================ */
const PW_HASH_KEY = 'cipherbureau_pw_hash';
const PW_ENABLED_KEY = 'cipherbureau_pw_enabled';

const gateCard = document.getElementById('gateCard');

function renderSetupScreen(){
  gateCard.innerHTML = `
    <div class="gate-seal">⚟</div>
    <h2>Set an access code</h2>
    <p class="sub">Optional — this only locks the toolkit on this device.</p>
    <div class="gate-error" id="gErr"></div>
    <div class="field-block">
      <span class="field-label">NEW CODE</span>
      <input type="password" id="setupPw1" placeholder="At least 4 characters">
    </div>
    <div class="field-block">
      <span class="field-label">CONFIRM CODE</span>
      <input type="password" id="setupPw2" placeholder="Repeat the code">
    </div>
    <button class="btn btn-primary" id="setupSaveBtn">Set code and continue</button>
    <div class="gate-links">
      <a id="skipProtectionLink">Continue without an access code</a>
    </div>
  `;
  document.getElementById('setupSaveBtn').addEventListener('click', async ()=>{
    const p1 = document.getElementById('setupPw1').value;
    const p2 = document.getElementById('setupPw2').value;
    const errEl = document.getElementById('gErr');
    if (p1.length<4){ errEl.textContent='Use at least 4 characters.'; errEl.classList.add('show'); return; }
    if (p1!==p2){ errEl.textContent='Those two codes are not the same.'; errEl.classList.add('show'); return; }
    const hash = await sha256(p1);
    await storeSet(PW_HASH_KEY, hash);
    await storeSet(PW_ENABLED_KEY, 'true');
    openApp();
  });
  document.getElementById('skipProtectionLink').addEventListener('click', async ()=>{
    await storeSet(PW_ENABLED_KEY, 'false');
    openApp();
  });
}

function renderUnlockScreen(){
  gateCard.innerHTML = `
    <div class="gate-seal">⚟</div>
    <h2>Cipher Bureau is locked</h2>
    <p class="sub">Enter the access code for this device.</p>
    <div class="gate-error" id="gErr"></div>
    <div class="field-block">
      <span class="field-label">ACCESS CODE</span>
      <input type="password" id="unlockPw" placeholder="Enter code" autofocus>
    </div>
    <button class="btn btn-primary" id="unlockBtn">Unlock</button>
    <div class="gate-links">
      <a id="resetFromGateLink">Forgot the code? Reset access</a>
    </div>
  `;
  const tryUnlock = async ()=>{
    const val = document.getElementById('unlockPw').value;
    const errEl = document.getElementById('gErr');
    const storedHash = await storeGet(PW_HASH_KEY);
    const hash = await sha256(val);
    if (hash === storedHash){ openApp(); }
    else { errEl.textContent = 'That code is not correct. Try again.'; errEl.classList.add('show'); }
  };
  document.getElementById('unlockBtn').addEventListener('click', tryUnlock);
  document.getElementById('unlockPw').addEventListener('keydown', (e)=>{ if (e.key==='Enter') tryUnlock(); });
  document.getElementById('resetFromGateLink').addEventListener('click', async ()=>{
    if (confirm('This clears the saved access code from this browser. Continue?')){
      await storeDelete(PW_HASH_KEY);
      await storeSet(PW_ENABLED_KEY, 'false');
      renderSetupScreen();
    }
  });
}

function openApp(){
  document.getElementById('gate').style.display = 'none';
  document.getElementById('app').style.display = 'block';
  initSecurityPanel();
}

async function initGate(){
  const enabled = await storeGet(PW_ENABLED_KEY);
  const hash = await storeGet(PW_HASH_KEY);
  if (enabled === 'true' && hash){
    renderUnlockScreen();
  } else if (hash && enabled !== 'false') {
    renderUnlockScreen();
  } else if (!hash) {
    renderSetupScreen();
  } else {
    openApp();
  }
}

/* ---- Security panel (inside the unlocked app) ---- */
async function initSecurityPanel(){
  const enabled = (await storeGet(PW_ENABLED_KEY)) === 'true';
  const hash = await storeGet(PW_HASH_KEY);
  const sw = document.getElementById('protectSwitch');
  const changeBlock = document.getElementById('changePwBlock');
  sw.classList.toggle('on', enabled);
  changeBlock.style.display = enabled ? 'block' : 'none';

  sw.onclick = async ()=>{
    const currentlyOn = sw.classList.contains('on');
    if (!currentlyOn){
      // turning on
      const existingHash = await storeGet(PW_HASH_KEY);
      if (existingHash){
        await storeSet(PW_ENABLED_KEY, 'true');
        sw.classList.add('on');
        changeBlock.style.display = 'block';
      } else {
        const p1 = prompt('Set an access code (at least 4 characters):');
        if (p1 === null) return;
        if (p1.length<4){ alert('Use at least 4 characters.'); return; }
        const p2 = prompt('Confirm the code:');
        if (p1 !== p2){ alert('Those two codes are not the same — nothing was saved.'); return; }
        await storeSet(PW_HASH_KEY, await sha256(p1));
        await storeSet(PW_ENABLED_KEY, 'true');
        sw.classList.add('on');
        changeBlock.style.display = 'block';
      }
    } else {
      await storeSet(PW_ENABLED_KEY, 'false');
      sw.classList.remove('on');
      changeBlock.style.display = 'none';
    }
  };

  document.getElementById('updatePwBtn').onclick = async ()=>{
    const cur = document.getElementById('currentPwInput').value;
    const n1 = document.getElementById('newPwInput').value;
    const n2 = document.getElementById('confirmPwInput').value;
    const statusEl = document.getElementById('pwUpdateStatus');
    const storedHash = await storeGet(PW_HASH_KEY);
    const curHash = await sha256(cur);
    if (storedHash && curHash !== storedHash){ statusEl.style.color='var(--rust)'; statusEl.textContent='Current code is incorrect.'; return; }
    if (n1.length<4){ statusEl.style.color='var(--rust)'; statusEl.textContent='New code needs at least 4 characters.'; return; }
    if (n1!==n2){ statusEl.style.color='var(--rust)'; statusEl.textContent='The new codes are not the same.'; return; }
    await storeSet(PW_HASH_KEY, await sha256(n1));
    await storeSet(PW_ENABLED_KEY, 'true');
    statusEl.style.color='var(--sage)'; statusEl.textContent='Access code updated — use the new code next time.';
    document.getElementById('currentPwInput').value='';
    document.getElementById('newPwInput').value='';
    document.getElementById('confirmPwInput').value='';
  };

  document.getElementById('resetPwBtn').onclick = async ()=>{
    if (confirm('This clears the saved access code and turns off locking on this device. Continue?')){
      await storeDelete(PW_HASH_KEY);
      await storeSet(PW_ENABLED_KEY, 'false');
      const swEl = document.getElementById('protectSwitch');
      swEl.classList.remove('on');
      document.getElementById('changePwBlock').style.display='none';
      const statusEl = document.getElementById('pwUpdateStatus');
      statusEl.style.color='var(--sage)';
      statusEl.textContent='Access code cleared.';
    }
  };
}

initGate();

})();
