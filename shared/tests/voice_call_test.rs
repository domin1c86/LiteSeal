use liteseal_shared::{
    crypto::{self, KeyPair},
    trusted_device::{Anchor, DeviceIdentity, DeviceState},
    voice_call::{self, CallError, Envelope, Header, Kind, ReplayFence, SignalSpec, LIFETIME_MS},
};
fn identity(account: &str) -> (KeyPair, DeviceState) {
    let keys = crypto::generate_keypair().unwrap();
    let state = DeviceState::pin(Anchor {
        origin: "https://synthetic.example".into(),
        account: account.into(),
        root: DeviceIdentity::from_keys(format!("{account}-root"), &keys),
    })
    .unwrap();
    (keys, state)
}
fn sdp() -> String {
    format!("v=0\r\no=- 1 1 IN IP4 0.0.0.0\r\ns=-\r\nt=0 0\r\nm=audio 9 UDP/TLS/RTP/SAVPF 111\r\na=ice-ufrag:synthetic\r\na=ice-pwd:synthetic-test-only-password\r\na=fingerprint:sha-256 {}\r\na=rtcp-mux\r\na=rtpmap:111 opus/48000/2\r\n", vec!["AA";32].join(":"))
}
fn envelope(
    a: &KeyPair,
    sa: &DeviceState,
    sb: &DeviceState,
    sequence: u64,
    kind: Kind,
) -> Envelope {
    Envelope::seal(
        Header::new(
            sa,
            &sa.anchor().root.device_id,
            sb,
            &sb.anchor().root.device_id,
            SignalSpec {
                id: "a".repeat(64),
                sequence,
                sent_at: 1000,
                kind,
            },
        )
        .unwrap(),
        sa,
        sb,
        a,
        if matches!(kind, Kind::Offer | Kind::Answer | Kind::Restart) {
            Some(sdp())
        } else {
            None
        },
    )
    .unwrap()
}
#[test]
fn audio_fingerprint_and_whole_signal_are_authenticated_before_use() {
    let (a, sa) = identity("alice");
    let (b, sb) = identity("bob");
    let wire = envelope(&a, &sa, &sb, 1, Kind::Offer);
    let opened = wire.open(&sa, &sb, &b, 1001).unwrap();
    assert_eq!(opened.sdp.as_deref(), Some(sdp().as_str()));
    let serialized = serde_json::to_string(&wire).unwrap();
    assert!(!serialized.contains("fingerprint"));
    assert!(!serialized.contains("ice-pwd"));
    let mut changed = wire.clone();
    changed.ciphertext[40] ^= 1;
    assert!(changed.open(&sa, &sb, &b, 1001).is_err());
    let mut changed = wire.clone();
    changed.header.kind = Kind::Answer;
    assert!(changed.open(&sa, &sb, &b, 1001).is_err());
    let mut changed = wire.clone();
    changed.header.peer = "mallory".into();
    assert!(changed.open(&sa, &sb, &b, 1001).is_err());
    let (wrong, wrong_state) = identity("bob");
    assert!(wire.open(&sa, &wrong_state, &wrong, 1001).is_err());
    assert!(matches!(
        wire.open(&sa, &sb, &b, 1000 + LIFETIME_MS),
        Err(CallError::Expired)
    ));
    assert!(matches!(
        wire.open(&sa, &sb, &b, 999),
        Err(CallError::Expired)
    ));
    let mut changed = wire.clone();
    changed.signature.truncate(63);
    assert!(changed.open(&sa, &sb, &b, 1001).is_err());
}
#[test]
fn audio_only_shape_rejects_missing_weak_or_conflicting_fingerprints_and_video() {
    let good = sdp();
    voice_call::validate_sdp(&good).unwrap();
    for changed in [
        good.replace("sha-256", "sha-1"),
        good.replace("AA:AA", "ZZ:AA"),
        good.replace("a=fingerprint:", "a=unknown:"),
        good.clone() + "m=video 9 UDP/TLS/RTP/SAVPF 96\r\n",
        good.clone() + "a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:secret\r\n",
        good.replace("UDP/TLS/RTP/SAVPF", "RTP/AVP"),
        good.replace("a=rtcp-mux\r\n", ""),
    ] {
        assert!(voice_call::validate_sdp(&changed).is_err());
    }
    let conflict =
        good.clone() + &format!("a=fingerprint:sha-256 {}\r\n", vec!["BB"; 32].join(":"));
    assert!(voice_call::validate_sdp(&conflict).is_err());
    assert!(voice_call::validate_sdp(&"x".repeat(voice_call::MAX_SDP + 1)).is_err());
}
#[test]
fn authenticated_duplicate_is_idempotent_but_gap_replacement_and_terminal_restart_fail() {
    let (a, sa) = identity("alice");
    let (b, sb) = identity("bob");
    let mut fence = ReplayFence::default();
    let first = envelope(&a, &sa, &sb, 1, Kind::Offer);
    first.open(&sa, &sb, &b, 1001).unwrap();
    assert!(fence.admit(&first).unwrap());
    assert!(!fence.admit(&first).unwrap());
    assert!(fence
        .admit(&envelope(&a, &sa, &sb, 1, Kind::Offer))
        .is_err());
    assert!(fence
        .admit(&envelope(&a, &sa, &sb, 3, Kind::Restart))
        .is_err());
    let last = envelope(&a, &sa, &sb, 2, Kind::Hangup);
    last.open(&sa, &sb, &b, 1001).unwrap();
    assert!(fence.admit(&last).unwrap());
    assert!(!fence.admit(&last).unwrap());
    assert!(fence
        .admit(&envelope(&a, &sa, &sb, 3, Kind::Restart))
        .is_err());
}
#[test]
fn admission_and_stop_are_separate_proofs_bound_to_exact_original_participants() {
    use voice_call::{Admission, Stop};
    let (a, sa) = identity("alice");
    let (b, sb) = identity("bob");
    let signal = envelope(&a, &sa, &sb, 1, Kind::Offer);
    let admission = Admission::make(signal.header.clone(), &a).unwrap();
    admission.verify(&sa, &sb).unwrap();
    admission.fresh(1001).unwrap();
    assert!(admission.fresh(999).is_err());
    assert!(admission.fresh(1000 + LIFETIME_MS).is_err());
    let mut reused = admission.clone();
    reused.signature = signal.signature;
    assert!(reused.verify(&sa, &sb).is_err());
    for (member, keys) in [
        (&admission.header.source, &a),
        (&admission.header.target, &b),
    ] {
        let stop = Stop::make(admission.clone(), member.clone(), keys).unwrap();
        stop.verify(&sa, &sb).unwrap();
        let mut changed = stop.clone();
        changed.admission.header.id = "b".repeat(64);
        assert!(changed.verify(&sa, &sb).is_err());
        let mut changed = stop.clone();
        changed.signature = admission.signature.clone();
        assert!(changed.verify(&sa, &sb).is_err());
    }
    assert!(Stop::make(admission.clone(), admission.header.target.clone(), &a).is_err());
    let mut changed = admission;
    changed.header.kind = Kind::Hangup;
    assert!(changed.verify(&sa, &sb).is_err());
}
