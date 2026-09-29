import { createRoot } from 'react-dom/client';
import App from '../src/App';
import AppLock from '../src/components/AppLock';
import Login from '../src/components/Login';
import StorageManager from '../src/components/StorageManager';
import AccountPanel from '../src/components/AccountPanel';
import OrganizerPanel from '../src/components/OrganizerPanel';
import AddContact from '../src/components/AddContact';
import '../src/theme.css';
const root=createRoot(document.getElementById('root')!);
const enc=(s:string)=>Array.from(new TextEncoder().encode(s));
const me='demo-owner', peer='demo-lin';const now=Date.now();
const contacts:any[]=[{user_id:peer,username:'林予安',public_key:Array(32).fill(2),ed25519_pk:Array(32).fill(3),trust_state:'verified',fingerprint:'A13F82BC09D7E4F6123C88AA901B72DE',key_changed:false,added_at:now},{user_id:'demo-zhou',username:'周可宁',public_key:Array(32).fill(4),ed25519_pk:Array(32).fill(5),trust_state:'unverified',fingerprint:'B32C10AA9D7E8F64128C777A902F23DB',key_changed:false,added_at:now}];
const rows=['明天的讨论定在 19:00，可以吗？','可以。我把需要确认的事项整理好了。','先核对两组指纹，再开始发送敏感内容。'].map((text,i)=>({id:'message-'+i,conversation_id:'dm:demo-lin:demo-owner',sender_id:i===1?me:peer,sender_device_id:i===1?'device-owner':'device-lin',sender_seq:i+1,timestamp:now-60000*(3-i),message_type:'text',local_state:i===1?'delivered':'received',ciphertext:enc(text),signature:[],prev_hash:[]}));
const organizer={version:1,aliases:{},lists:[{id:'work',name:'项目伙伴',peers:[peer]}],favorites:[{messageId:'message-0',peerId:peer}],notes:`下次讨论：
1. 核对邀请对象与设备指纹
2. 讨论资料只在本机保存
3. 确认投票结果后安排会议`};
let locked=false, signedIn=true, generation=0, attachment=false, imageMode=false;
const api:any={
 load_identity:async()=>{if(!signedIn)throw new Error('No saved keypair');return {user_id:me,device_id:'device-owner',token:'synthetic-session',refresh_token:'synthetic-refresh',server_url:'http://localhost:3000',public_key:Array(32).fill(1),ed25519_pk:Array(32).fill(9),saved:true}},
 get_contacts:async()=>contacts,get_public_profile:async({userId}:any)=>({user_id:userId,username:contacts.find(c=>c.user_id===userId)?.username??'demo-owner',display_name:contacts.find(c=>c.user_id===userId)?.username??'陈知远',avatar_png:null}),
 get_personal_organizer:async()=>JSON.stringify(organizer),get_conversation_preferences:async()=>contacts.map((c,i)=>({peer_id:c.user_id,pinned:i===0,archived:false,muted:false,draft:[]})),
 get_conversation_summaries:async()=>[{conversation_id:rows[0].conversation_id,latest:rows[2],unread_count:1}],
 get_local_message_page:async(a:any)=>a.beforeTimestamp||a.before_timestamp?[]:[...rows].reverse(),get_message_context:async()=>rows,
 decrypt_message:async(a:any)=>a.ciphertext,encrypt_message:async(a:any)=>a.plaintext??[],get_message_operations:async()=>[],get_locally_deleted_ids:async()=>[],get_reactions:async()=>[{target_id:"message-0",actor:peer,emoji:"👍"}],get_read_receipts:async()=>[],
 connect_relay:async()=>({connected:true}),poll_messages:async()=>({messages:[],events:[]}),sync_message_operations:async()=>0,sync_reactions:async()=>0,sync_read_receipts:async()=>0,
 get_groups:async()=>({groups:[],invitations:[],errors:[],next_cursor:null}),get_read_receipt_enabled:async()=>false,get_typing_enabled:async()=>false,take_notification_target:async()=>null,
 list_scheduled_messages:async()=>[{id:'task-1',peer_id:peer,due_at:now+3600000,text:'提醒：今晚讨论前请先查看议程。',state:'scheduled',error:'',sealed:false}],
 list_attachment_tasks:async()=>attachment?[{id:'attachment-1',peer_id:peer,message_id:'file-message',name:imageMode?'讨论流程示意.png':'会议议程.pdf',size:184320,mime:imageMode?'image/png':'application/pdf',offset:0,total:184360,direction:'upload'}]:[],
 list_contact_requests:async()=>[{peer_id:'demo-new',username:'许星禾',status:'pending',count:2}],list_account_sessions:async()=>[{id:'session-1',name:'Windows desktop',device_id:'device-owner',current:true,revoked:false,expires_at:'2026-10-01 12:00'}],
 get_storage_stats:async()=>({message_count:286,ciphertext_bytes:524288,attachment_count:8,attachment_bytes:5242880,conversation_count:3,total_bytes:5767168}),
 attachment_cache_stats:async()=>({cache_bytes:5242880,database_allocated:10485760,database_reusable:1048576,disk_bytes:12582912,limit:268435456}),
 app_lock_state:async()=>locked,validate_invite:async()=>true,search_users:async()=>[{user_id:'demo-new',username:'许星禾',public_key:Array(32).fill(6),ed25519_pk:Array(32).fill(7)}],
};
api.preview_attachment_task=async()=>{const canvas=document.createElement('canvas');canvas.width=400;canvas.height=240;const ctx=canvas.getContext('2d')!;ctx.fillStyle='#eef4fa';ctx.fillRect(0,0,400,240);ctx.fillStyle='#244969';ctx.font='24px sans-serif';ctx.fillText('小组讨论 · 演示图片',35,55);ctx.font='18px sans-serif';ctx.fillText('核实身份 → 讨论 → 投票',35,125);ctx.fillText('此图不含真实用户数据',35,190);return canvas.toDataURL('image/png');};
window.desktop=new Proxy(api,{get:(target,key:string)=>target[key]??(async()=>null)}) as any;
const sleep=(ms=250)=>new Promise(r=>setTimeout(r,ms));
const btn=(text:string)=>Array.from(document.querySelectorAll<HTMLButtonElement>('button')).find(b=>b.textContent?.trim()===text);
async function click(text:string){const b=btn(text);if(!b)throw new Error('missing '+text);const menu=b.closest('details');if(menu){menu.open=true;await sleep(40);}b.click();await sleep();}
async function fill(selector:string,value:string){const node=document.querySelector(selector) as HTMLInputElement; if(!node)throw new Error('input missing '+selector);Object.getOwnPropertyDescriptor(node.tagName==='TEXTAREA'?HTMLTextAreaElement.prototype:HTMLInputElement.prototype,'value')!.set!.call(node,value);node.dispatchEvent(new Event('input',{bubbles:true}));await sleep();}
const noop=()=>{};
(window as any).tour=async(mode:string)=>{
 imageMode=mode==='image-preview'; attachment=mode==='attachments'||imageMode;locked=mode==='lock';signedIn=true;root.render(<App key={++generation}/>);await sleep(500);
 if(mode==='login'||mode==='register'){root.render(<Login key={++generation} onLogin={noop}/>);await sleep();if(mode==='register'){await click('Register');}return;}
 if(mode==='lock'){root.render(<AppLock key={++generation}><App/></AppLock>);await sleep();return;}
 if(mode==='storage'){root.render(<StorageManager onClose={noop}/>);await sleep();return;}
 if(mode.startsWith('account')){root.render(<AccountPanel key={++generation} userId={me} contacts={contacts} typingEnabled={false} onTypingEnabledChange={noop} onClose={noop} onContactsChanged={noop} onLogout={noop}/>);await sleep();if(mode==='account-security'){const panel=document.querySelector('[role=dialog]')!;panel.scrollTop=panel.scrollHeight;}return;}
 if(mode==='organizer'){root.render(<OrganizerPanel organizer={{value:organizer,ready:true,busy:false,error:null,update:async()=>{}} as any} userId={me} contacts={contacts} onClose={noop} onOpen={noop}/>);await sleep();return;}
 if(mode==='add-contact'){root.render(<AddContact serverUrl="http://localhost:3000" token="synthetic" userId={me} contacts={contacts} onClose={noop} onAdded={noop}/>);await sleep();const input=document.querySelector('input')!;await fill('input','许星禾');input.closest('form')?.dispatchEvent(new Event('submit',{bubbles:true,cancelable:true}));await sleep();return;}
 if(mode==='contacts')await click('contacts');
 (document.querySelector('.contact-row') as HTMLElement)?.click();await sleep(500);
 if(mode==='search'){await click('搜索历史（Ctrl+F）');await fill('[aria-label="搜索关键词"]','讨论');await sleep(800);}
 if(mode==='scheduled'){const b=Array.from(document.querySelectorAll<HTMLButtonElement>('button')).find(b=>b.textContent?.startsWith('本机定时文字'))!;b.click();await sleep();b.scrollIntoView();}
 if(mode==='quote')await click('回复');
 if(mode==='image-preview'){await click('发送前预览');document.querySelector('[aria-label="发送加密附件"]')?.scrollIntoView();}
 if(mode==='edit')await click('编辑');
 if(mode==='revoke')await click('撤回');
 if(mode==='forward')await click('转发');
 if(mode==='delete')await click('从本机删除');
 if(mode==='emoji'){(document.querySelector('[aria-label="选择 emoji"]') as HTMLButtonElement).click();await sleep();}
 if(mode==='attachments')document.querySelector('[aria-label="发送加密附件"]')?.scrollIntoView();
 if(['edit','revoke','forward','delete'].includes(mode))document.querySelector('[role="dialog"]')?.scrollIntoView();
};

(window as any).checkStyleInteractions=async()=>{
 const check=(value:unknown,label:string)=>{if(!value)throw new Error(label);};
 await (window as any).tour('chat');
 const menu=document.querySelector('.message-tools details') as HTMLDetailsElement;
 check(!!menu,'message actions exist');
 check(document.querySelector('[aria-label=已有回应]')?.checkVisibility(),'existing reactions remain visible without opening actions');
 (menu.querySelector('summary') as HTMLElement).click();await sleep(80);
 check(menu.open,'message menu opens');
 const copy=btn('复制')!;const box=copy.getBoundingClientRect();const log=document.querySelector('.chat-messages')!.getBoundingClientRect();
 check(box.top>=log.top && box.bottom<=log.bottom,'first-message menu remains inside scroll area');
 menu.dispatchEvent(new KeyboardEvent('keydown',{key:'Escape',bubbles:true}));await sleep();
 check(!menu.open,'Escape closes menu');
 await click('编辑');
 const dialog=document.querySelector('dialog')!;
 check(dialog?.open && dialog.matches(':modal'),'editing uses a modal dialog');
 check(dialog.contains(document.activeElement),'focus is inside modal');
 await fill('[aria-label="编辑后的正文"]','测试编辑草稿');
 check((document.querySelector('[aria-label="编辑后的正文"]') as HTMLTextAreaElement).value==='测试编辑草稿','edit text remains editable');
 let rejectOperation: ((reason:Error)=>void)|undefined;
 api.submit_message_operation=()=>new Promise((_resolve,reject)=>{rejectOperation=reject;});
 await click('保存编辑');
 dialog.dispatchEvent(new KeyboardEvent('keydown',{key:'Escape',bubbles:true}));
 dialog.dispatchEvent(new Event('cancel',{cancelable:true}));await sleep(50);
 check(dialog.isConnected && dialog.open,'busy modal cannot close through Escape');
 rejectOperation!(new Error('模拟服务拒绝编辑'));
 await sleep();
 check(dialog.textContent?.includes('模拟服务拒绝编辑'),'submission failure remains visible inside modal');
 delete api.submit_message_operation;
 dialog.dispatchEvent(new Event('cancel',{cancelable:true}));await sleep();
 check(!document.querySelector('dialog'),'Escape cancellation closes dialog');
 check(document.activeElement?.tagName==='SUMMARY','focus returns to message actions');
 const contactMenu=document.querySelector('.contact-actions details') as HTMLDetailsElement;
 (contactMenu.querySelector('summary') as HTMLElement).click();await sleep();check(contactMenu.open,'contact actions open');
 document.body.dispatchEvent(new PointerEvent('pointerdown',{bubbles:true}));check(!contactMenu.open,'outside click dismisses menu');
 return ['message actions and boundary placement','Escape and outside dismissal','modal focus containment and restoration','editable message form','busy Escape guard and visible submission failure','visible reaction chips'];
};
