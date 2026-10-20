import {getStore} from '@netlify/blobs';
import {createHmac,timingSafeEqual} from 'node:crypto';
const headers={'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store'};
const json=(data,status=200,extra={})=>new Response(JSON.stringify(data),{status,headers:{...headers,...extra}});
const digest=(s,key)=>createHmac('sha256',key).update(s).digest();
const sign=(s,key)=>digest(s,key).toString('hex');
function authorized(request,key){const cookie=request.headers.get('cookie')||'';const token=cookie.split(';').map(x=>x.trim()).find(x=>x.startsWith('rawabti_session='))?.slice(16);if(!token)return false;const [expires,signature]=token.split('.');if(!/^\d+$/.test(expires)||Number(expires)<Date.now()||!/^[a-f0-9]{64}$/.test(signature||''))return false;return timingSafeEqual(Buffer.from(signature,'hex'),Buffer.from(sign(expires,key),'hex'));}
export function validProfile(p){return p&&typeof p==='object'&&typeof p.name==='string'&&p.name.trim().length>0&&p.name.length<=70&&typeof p.bio==='string'&&p.bio.length<=250&&typeof p.location==='string'&&p.location.length<=80&&/^#[a-f0-9]{6}$/i.test(p.color)&&typeof p.image==='string'&&p.image.length<=2900000&&(!p.image||/^data:image\/(png|jpeg|webp|gif);base64,[a-z0-9+/=]+$/i.test(p.image))&&Array.isArray(p.links)&&p.links.length<=50&&p.links.every(l=>{if(!l||!['title','subtitle','url','icon'].every(k=>typeof l[k]==='string')||!l.title.trim()||l.title.length>120||l.subtitle.length>250||l.icon.length>16||l.url.length>2048)return false;try{return ['https:','http:','mailto:','tel:'].includes(new URL(l.url).protocol)}catch{return false}})}
export function createHandler(storeFactory=()=>getStore({name:'rawabti',consistency:'strong'})){return async function handler(request){
 const url=new URL(request.url),path=url.pathname.replace(/^.*\/profile/, '').replace(/^\/api/,'')||'/';
 const key=process.env.ADMIN_PASSWORD;
 if(request.method==='GET'&&path==='/session')return json({authenticated:!!key&&authorized(request,key),configured:!!key});
 if(request.method==='POST'&&path==='/logout')return json({ok:true},200,{'Set-Cookie':'rawabti_session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0'});
 if(request.method!=='GET'&&request.headers.get('origin')!==url.origin)return json({error:'طلب غير مسموح'},403);
 if(request.method==='POST'&&path==='/login'){
  if(!key)return json({error:'أضف ADMIN_PASSWORD في إعدادات Netlify لتفعيل لوحة التحكم.'},503);
  let body;try{body=await request.json()}catch{return json({error:'بيانات غير صالحة'},400)}
  if(typeof body.password!=='string'||body.password.length>1000||!timingSafeEqual(digest(body.password,key),digest(key,key)))return json({error:'كلمة المرور غير صحيحة'},401);
  const expires=String(Date.now()+86400000);return json({ok:true},200,{'Set-Cookie':`rawabti_session=${expires}.${sign(expires,key)}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=86400`});
 }
 try{
  const store=storeFactory();
  if(request.method==='GET'&&path==='/')return json({profile:await store.get('profile',{type:'json'})});
  if(request.method==='PUT'&&path==='/'){
   if(!key||!authorized(request,key))return json({error:'سجّل دخولك الأول.'},401);
   const raw=await request.text();if(raw.length>3000000)return json({error:'حجم البيانات كبير جدًا'},413);
   let profile;try{profile=JSON.parse(raw)}catch{return json({error:'بيانات غير صالحة'},400)}
   if(!validProfile(profile))return json({error:'راجع بياناتك: اسم مطلوب، روابط صحيحة، وبحد أقصى ٥٠ رابط.'},400);
   await store.setJSON('profile',profile);return json({ok:true});
  }
  return json({error:'غير موجود'},404);
 }catch{return json({error:'تعذر الوصول للحفظ. جرّب تاني بعد لحظات.'},503)}
}
}
export default createHandler();
