extern crate libc;

include!(concat!(env!("OUT_DIR"), "/olm.rs"));

use std::ffi::CString;

pub struct GroupSession{
    participants: Vec<Participant>,
}

struct Participant {
    id: String,
    session: *mut OlmSession,
}

impl GroupSession {
    #[no_mangle]
    pub unsafe extern "C" fn  new() -> GroupSession {
        return GroupSession{
            participants: Vec::new(),
        }
    }

    pub unsafe extern "C" fn add_participant(&mut self, id: *mut i8, participant: *mut OlmSession) -> size_t {
        let idstr = CString::from_raw(id);
        let pid = idstr.into_string();

        if pid.is_err() {
            return 1
        };

        self.participants.push(Participant{
            id: pid.unwrap(),
            session: participant
        });

        return 0;
    }

    pub unsafe extern "C" fn encrypt_size(&mut self, ctlen: size_t) -> size_t {

    }

    pub unsafe extern "C" fn encrypt(&mut self, )
}

#[no_mangle]
pub unsafe extern "C" fn create_group_session() -> size_t {
    return olm_account_size();
}
