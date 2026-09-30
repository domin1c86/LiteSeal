import { getDesktopApi } from "./desktopApi";
export type AttachmentTarget={kind:"direct";id:string}|{kind:"group";id:string};
export function attachmentApi(target:AttachmentTarget){const api=getDesktopApi(),group=target.kind==="group",id=target.id;return{
  tasks:()=>group?api.group_attachment_tasks({groupId:id}):api.list_attachment_tasks({}).then(rows=>rows.filter(r=>r.peer_id===id)),
  select:()=>group?api.select_group_attachment({groupId:id}):api.select_attachment({peerId:id}),
  stage:(file:File)=>group?api.stage_group_attachment_file({groupId:id,file}):api.stage_attachment_file({peerId:id,file}),
  paste:()=>group?api.stage_group_clipboard_image({groupId:id}):api.stage_clipboard_image({peerId:id}),
  voice:(encoded:string,durationMs:number)=>group?api.stage_group_recorded_audio({groupId:id,encoded,durationMs}):api.stage_recorded_audio({peerId:id,encoded,durationMs}),
  step:(blob:string)=>group?api.group_attachment_step({groupId:id,id:blob}):api.attachment_step({id:blob}),
  publish:(blob:string)=>group?api.publish_group_attachment({groupId:id,id:blob}):api.publish_attachment({id:blob}),
  finish:async(blob:string)=>{if(!group)await api.forget_attachment_task({id:blob});},
  cancel:(blob:string)=>group?api.cancel_group_attachment({groupId:id,id:blob}):api.forget_attachment_task({id:blob}),
  preview:(blob:string)=>group?api.export_group_attachment({groupId:id,id:blob,preview:true,media:"image"}):api.preview_attachment_task({id:blob}),
  begin:(messageId:string)=>group?api.begin_group_attachment_download({groupId:id,messageId}):api.begin_attachment_download({messageId}),
  export:(messageId:string,blob:string,media:false|"image"|"audio")=>group?api.export_group_attachment({groupId:id,id:blob,preview:!!media,media:media||undefined}):api.export_attachment({messageId,preview:!!media,media:media||undefined}),
};}
