use serde::{Deserialize,Serialize};
#[derive(Clone,Serialize,Deserialize)]
pub struct Reaction {
    pub id:String, pub target_id:String, pub conversation_id:String,
    pub actor:String, pub device:String, pub peer:String,
    pub revision:i64, pub ciphertext:Vec<u8>, pub signature:Vec<u8>,
}
impl Reaction {
    pub fn signing_bytes(&self)->Vec<u8>{
        serde_json::to_vec(&("LiteSeal/reaction/v1",&self.id,&self.target_id,&self.conversation_id,&self.actor,&self.device,&self.peer,self.revision,&self.ciphertext)).expect("serializable reaction")
    }
}
#[derive(Clone,Serialize,Deserialize)]
pub struct ReactionDelivery { pub seq:i64, pub event:Reaction }
pub const EMOJI:[&str;7]=["","👍","❤️","😂","😮","😢","🙏"];
