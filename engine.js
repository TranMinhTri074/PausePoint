export const MAX_INPUT = 5000;
export const SOURCES = [
 {id:'vn-local',label:'Hải Phòng police warning: fake child-ID verification calls',date:'2026-10-01',url:'https://bocongan.gov.vn/bai-viet/cong-an-hai-phong-canh-bao-thu-doan-yeu-cau-dang-ki-dinh-danh-dien-tu-cho-tre-de-lua-dao-chiem-doat-tai-san-1790845850'},
 {id:'vn-patterns',label:'Viet Nam Ministry of Public Security: 2026 scam patterns',date:'2026-09-08',url:'https://www.bocongan.gov.vn/bai-viet/nang-cao-canh-giac-truoc-25-kich-ban-lua-dao-tren-khong-gian-mang-nam-2026-1788865614'},
 {id:'ftc-signs',label:'FTC: signs of a scam and independent verification',date:'2025-03',url:'https://consumer.ftc.gov/consumer-alerts/2025/03/what-are-signs-scam'},
 {id:'ftc-text',label:'FTC: check unexpected texts through a known contact channel',date:'2025-04-16',url:'https://consumer.ftc.gov/consumer-alerts/2025/04/unexpected-text-scam'},
 {id:'ftc-codes',label:'FTC: keep verification codes private',date:'2024-03',url:'https://consumer.ftc.gov/consumer-alerts/2024/03/whats-verification-code-why-would-someone-ask-me-it?page=0'},
 {id:'ftc-family',label:'FTC: independently verify family emergencies',date:'Reviewed 2026-10-22',url:'https://consumer.ftc.gov/articles/scammers-use-fake-emergencies-steal-your-money'},
 {id:'ftc-recovery',label:'FTC: steps after money or account access is shared',date:'Reviewed 2026-10-22',url:'https://consumer.ftc.gov/articles/what-do-if-you-were-scammed'},
 {id:'ftc-losses',label:'FTC: reported imposter-scam losses in 2025',date:'2026-06',url:'https://www.ftc.gov/news-events/news/press-releases/2026/06/ftc-data-show-people-reported-losing-3-point-5-billion-imposter-scams-2025'},
 {id:'mdn-url',label:'MDN: parsing the actual URL hostname',date:'Reviewed 2026-10-22',url:'https://developer.mozilla.org/en-US/docs/Web/API/URL/hostname'}
];

// Keep source offsets so displayed evidence comes from the original message.
export function normalizeWithMap(input) {
 let normalized='', starts=[], ends=[], offset=0;
 for(const char of input){
  const clean=char.normalize('NFD').replace(/\p{M}/gu,'').replace(/[đĐ]/g,'d').toLowerCase().replace(/[\u200B-\u200D\u2060\uFEFF]/g,'');
  for(const c of clean){normalized+=c;starts.push(offset);ends.push(offset+char.length);}
  offset+=char.length;
 }
 return {normalized,starts,ends};
}

const request=/(?:send|share|tell|give|read|forward|provide|confirm|reply|enter|gui|cung cap|doc|cho|nhap|xac nhan|chuyen tiep).{0,55}(?:otp|verification code|one.time code|passcode|password|pin\b|ma xac (?:minh|thuc)|mat khau)|(?:otp|verification code|password|ma xac thuc|mat khau).{0,45}(?:send|share|give|gui|cung cap|doc)/g;
const RULES=[
 {id:'code',priority:1,source:'ftc-codes',rx:request,negation:true},
 {id:'remote',priority:1,source:'vn-patterns',rx:/(?:install|download|open|cai dat|tai|mo).{0,40}(?:anydesk|teamviewer|quick.?support|remote.?access|remote.?control|apk\b|ung dung|dieu khien tu xa)|(?:screen.?share|chia se man hinh|dieu khien dien thoai)/g,negation:true},
 {id:'protect',priority:1,source:'ftc-signs',rx:/(?:transfer|move|send|chuyen|rut).{0,70}(?:safe account|secure account|protect your money|tai khoan an toan|bao ve (?:tien|tai khoan))/g,negation:true},
 {id:'upfront',priority:2,source:'vn-patterns',rx:/(?:pay|payment|deposit|fee|dong|nop|chuyen|dat coc).{0,55}(?:unlock|withdraw|refund|receive|job|training|activate|kich hoat|rut tien|hoan tien|nhan viec|nhan thuong)|(?:refund|job|hoan tien|nhan viec).{0,50}(?:pay first|deposit|fee|dat coc|nop phi|dong phi)/g,negation:true},
 {id:'secrecy',priority:2,source:'ftc-family',rx:/(?:do not tell|don't tell|dont tell|keep (?:it|this) secret|keep this between|dung noi|khong duoc noi|giu bi mat)/g},
 {id:'newnumber',priority:2,source:'ftc-family',rx:/(?:new number|lost my phone|broken phone|my phone broke|changed my number|so moi|mat dien thoai|hong dien thoai|doi so)/g},
 {id:'guarantee',priority:2,source:'vn-patterns',rx:/(?:guaranteed (?:profit|return)|risk.free (?:investment|profit)|double your money|cam ket loi nhuan|loi nhuan dam bao|dau tu khong rui ro|nhan doi so tien)/g},
 {id:'urgency',priority:3,source:'ftc-signs',rx:/(?:\burgent\b|immediately|right now|within \d+ minutes|act now|account.{0,15}(?:locked|suspended)|arrest|xac thuc gap|ngay lap tuc|khan cap|trong \d+ phut|bat giam|phong toa|khoa tai khoan)/g},
 {id:'authority',priority:3,source:'vn-local',rx:/(?:\bpolice\b|\bbank\b|\bcourt\b|government|tax office|school office|cong an|ngan hang|toa an|co quan nha nuoc|nha truong|dinh danh dien tu)/g}
];

function negatedAt(text,start){
 const context=text.slice(Math.max(0,start-45),start);
 return /(?:do not|don't|dont|never|must not|should not|khong|dung|tuyet doi khong)\s+(?:ever\s+|bao gio\s+)?$/.test(context);
}

export function inspectLinks(text){
 const regex=/(?:https?:\/\/|www\.)[^\s<>"']+/gi, links=[];
 for(const match of text.matchAll(regex)){
  const original=match[0].replace(/[.,!;?]+$/,'');
  let url;try{url=new URL(original.startsWith('www.')?'https://'+original:original);}catch{links.push({raw:original,hostname:null,signals:['invalid'],start:match.index,end:match.index+original.length});continue;}
  const signals=[];
  if(url.username||url.password)signals.push('userinfo');
  if(url.protocol==='http:')signals.push('unencrypted');
  if(/(?:^|\.)xn--/i.test(url.hostname))signals.push('international');
  if(/^(?:bit\.ly|tinyurl\.com|t\.co|is\.gd|shorturl\.at|cutt\.ly)$/i.test(url.hostname))signals.push('shortener');
  if(/^(?:\d{1,3}\.){3}\d{1,3}$/.test(url.hostname)||url.hostname.startsWith('['))signals.push('ip');
  if(url.port)signals.push('port');
  links.push({raw:original,hostname:url.hostname,signals,start:match.index,end:match.index+original.length});
 }
 return links;
}

export function analyze(input,context={}){
 if(typeof input!=='string')throw new TypeError('Message must be text.');
 if(input.length>MAX_INPUT)throw new RangeError('Use at most 5,000 characters.');
 const norm=normalizeWithMap(input), signals=[];
 for(const rule of RULES){
  rule.rx.lastIndex=0;
  let evidence=[];
  for(const m of norm.normalized.matchAll(rule.rx)){
   if(rule.negation&&negatedAt(norm.normalized,m.index))continue;
   const start=norm.starts[m.index],end=norm.ends[m.index+m[0].length-1];
   if(Number.isFinite(start)&&Number.isFinite(end))evidence.push({start,end,text:input.slice(start,end)});
   if(evidence.length>=3)break;
  }
  if(evidence.length)signals.push({id:rule.id,priority:rule.priority,source:rule.source,evidence,origin:'text'});
 }
 const manual=[['code','code'],['install','remote'],['money','money'],['rush','urgency'],['secret','secrecy']];
 for(const [key,id] of manual){if(context[key]===true&&!signals.some(s=>s.id===id))signals.push({id,priority:id==='code'||id==='remote'?1:2,source:id==='code'?'ftc-codes':'ftc-signs',evidence:[],origin:'answer'});}
 const links=inspectLinks(input);
 if(links.some(link=>link.signals.length))signals.push({id:'link',priority:2,source:'mdn-url',origin:'link',evidence:[]});
 if(/[\u202A-\u202E\u2066-\u2069\u200B-\u200D\u2060\uFEFF]/u.test(input))signals.push({id:'hidden',priority:2,source:'mdn-url',origin:'text',evidence:[]});
 signals.sort((a,b)=>a.priority-b.priority||a.id.localeCompare(b.id));
 const ids=new Set(signals.map(s=>s.id));
 const actions=['pause'];
 if(ids.has('code'))actions.push('codes');
 if(ids.has('remote'))actions.push('install');
 if(['protect','upfront','money','guarantee'].some(id=>ids.has(id)))actions.push('money');
 if(ids.has('newnumber'))actions.push('family');else actions.push('independent');
 if(links.length)actions.push('links');
 actions.push('trusted');
 return {signals,links,actions:[...new Set(actions)],hasInput:!!input.trim()||manual.some(([k])=>context[k]===true),verdict:'unverified',limits:['No identity verification','No website visit or reputation lookup','Rules can miss scams or flag legitimate messages','English and Vietnamese patterns only']};
}

// Export intentionally omits raw text, matched phrases, links and personal names.
export function buildPlanText(result,lang,labels){
 return ['PAUSEPOINT — INDEPENDENT VERIFICATION PLAN',labels.unverified,'',labels.exportPrivacy,'',...result.actions.map((id,i)=>`${i+1}. ${labels.actions[id]}`),'',labels.scope,'', 'Sources: https://consumer.ftc.gov/consumer-alerts/2025/03/what-are-signs-scam', 'https://bocongan.gov.vn/',`Language: ${lang}`].join('\n');
}
