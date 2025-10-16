// Shared core: range parsing, constraints, combinations, greedy allocation
// Supports 4 optional ranges (range1..range4)

function escapeHtml(str){
  return String(str)
    .replaceAll("&","&amp;")
    .replaceAll("<","&lt;")
    .replaceAll(">","&gt;")
    .replaceAll('"',"&quot;")
    .replaceAll("'","&#039;");
}

function formatRange(r){
  if(!r) return "—";
  const [a,b]=r;
  return a===b?`${a}`:`${a}-${b}`;
}

function parseRange(input){
  const s=(input||"").trim();
  if(!s) return null;
  const parts=s.split("-").map(p=>p.trim()).filter(Boolean);
  if(parts.length===1){
    const n=Number(parts[0]);
    if(!Number.isInteger(n)) throw new Error(`Invalid range: "${input}"`);
    return [n,n];
  }
  if(parts.length===2){
    let a=Number(parts[0]), b=Number(parts[1]);
    if(!Number.isInteger(a)||!Number.isInteger(b)) throw new Error(`Invalid range: "${input}"`);
    if(a>b) [a,b]=[b,a];
    return [a,b];
  }
  throw new Error(`Invalid range: "${input}"`);
}

function rangesCompatible(map, combo){
  const dims=["range1","range2","range3","range4"];
  for(const dim of dims){
    let hasAny=false, low=-Infinity, high=Infinity;
    for(const key of combo){
      const r = map[key][dim];
      if(!r) continue;
      hasAny=true;
      low = Math.max(low, r[0]);
      high = Math.min(high, r[1]);
      if(low>high) return false;
    }
    if(hasAny && low>high) return false;
  }
  return true;
}

function soddisfaBisogni(map, sottoinsieme){
  const risultato={}, rimanenti={};
  for(const k of sottoinsieme) rimanenti[k]=map[k].fondi;

  for(const persona of sottoinsieme){
    let need = map[persona].bisogno;
    risultato[persona]=[];
    const poss=(map[persona].possibili_donatori||[]).filter(d=>sottoinsieme.includes(d));
    const ord=[...poss].sort((a,b)=>(rimanenti[b]??0)-(rimanenti[a]??0));
    for(const d of ord){
      if(need<=0) break;
      const avail=rimanenti[d]??0;
      if(avail>0){
        const give=Math.min(need,avail);
        risultato[persona].push([d,give]);
        rimanenti[d]=avail-give;
        need-=give;
      }
    }
    if(need>0) return null; // someone still needs more -> fail
  }
  return risultato;
}

function* combinations(arr,k,start=0,prefix=[]){
  if(prefix.length===k){ yield prefix.slice(); return; }
  for(let i=start;i<=arr.length-(k-prefix.length);i++){
    prefix.push(arr[i]);
    yield* combinations(arr,k,i+1,prefix);
    prefix.pop();
  }
}

function trovaSottoinsieme(map,k){
  const keys=Object.keys(map);
  for(const combo of combinations(keys,k)){
    if(!rangesCompatible(map,combo)) continue;
    const res=soddisfaBisogni(map,combo);
    if(res) return { combo, risultato:res };
  }
  return null;
}

// Expose globals for inline/non-module scripts
window.escapeHtml = escapeHtml;
window.formatRange = formatRange;
window.parseRange = parseRange;
window.trovaSottoinsieme = trovaSottoinsieme;
