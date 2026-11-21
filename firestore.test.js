const {
  initializeTestEnvironment,
  assertFails,
  assertSucceeds,
} = require("@firebase/rules-unit-testing");
const { test, before, after, beforeEach } = require("node:test");
const fs = require("node:fs");

let testEnv;
const PROJECT_ID = process.env.GCP_PROJECT || "demo-no-project";
const ALICE_UID = "alice_123";
const BOB_UID = "bob_456";
const CHARLIE_UID = "charlie_789";

const [emulatorHost, emulatorPortStr] = (process.env.FIRESTORE_EMULATOR_HOST || "127.0.0.1:8085").split(":");
const emulatorPort = parseInt(emulatorPortStr, 10);

before(async () => {
  const rules = fs.readFileSync("./firestore.rules", "utf8");
  testEnv = await initializeTestEnvironment({
    projectId: PROJECT_ID,
    firestore: {
      rules,
      host: emulatorHost,
      port: emulatorPort,
    },
  });
});

after(async () => {
  if (testEnv) {
    await testEnv.cleanup();
  }
});

beforeEach(async () => {
  if (testEnv) {
    await testEnv.clearFirestore();
  }
});

function pastDate(msOffset = 5000) {
  return new Date(Date.now() - msOffset);
}

function validUserPublic(uid, discoverable = true) {
  const ts = pastDate(10000);
  return {
    userId: uid,
    displayName: `User ${uid}`,
    handle: `handle_${uid}`,
    bio: "Encrypted messaging",
    avatarPreset: "TEAL_SHIELD",
    publicKeyBase64: "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE1234567890abcdef",
    keyFingerprint: "A1B2-C3D4-E5F6-7890",
    online: true,
    lastSeenVisibility: "EVERYONE",
    discoverable,
    lastSeenAt: ts,
    createdAt: ts,
    updatedAt: ts,
  };
}

test("Unauthenticated user: denied across all collections", async () => {
  const unauth = testEnv.unauthenticatedContext().firestore();
  await assertFails(unauth.collection("users_public").where("discoverable", "==", true).get());
  await assertFails(unauth.collection("users_private").doc(ALICE_UID).get());
  await assertFails(unauth.collection("conversations").where("memberUids", "array-contains", ALICE_UID).get());
  await assertFails(unauth.collection("status_updates").where("audience", "==", "PUBLIC").get());
  await assertFails(unauth.collection("calls").where("memberUids", "array-contains", ALICE_UID).get());
});

test("users_public & users_private: split PII isolation and profile updates", async () => {
  const alice = testEnv.authenticatedContext(ALICE_UID).firestore();
  const bob = testEnv.authenticatedContext(BOB_UID).firestore();
  const ts = pastDate(10000);

  await assertSucceeds(alice.collection("users_public").doc(ALICE_UID).set(validUserPublic(ALICE_UID, true)));
  await assertSucceeds(
    alice.collection("users_private").doc(ALICE_UID).set({
      userId: ALICE_UID,
      email: "alice@example.com",
      phoneNumber: "+919876543210",
      phoneVerified: true,
      createdAt: ts,
      updatedAt: ts,
    })
  );

  // Bob can view Alice's public profile and list discoverable profiles, but NEVER Alice's private PII
  await assertSucceeds(bob.collection("users_public").doc(ALICE_UID).get());
  await assertSucceeds(bob.collection("users_public").where("discoverable", "==", true).get());
  await assertFails(bob.collection("users_public").get()); // unfiltered list fails
  await assertFails(bob.collection("users_private").doc(ALICE_UID).get());
  await assertFails(bob.collection("users_public").doc(ALICE_UID).update({ online: false, lastSeenAt: pastDate(1000), updatedAt: pastDate(1000) }));

  // Alice can update her presence
  await assertSucceeds(
    alice.collection("users_public").doc(ALICE_UID).update({
      online: false,
      lastSeenAt: pastDate(1000),
      updatedAt: pastDate(1000),
    })
  );

  // Reject ghost field / @DocumentId `id`
  await assertFails(
    alice.collection("users_public").doc("bad_doc").set({
      id: "bad_doc",
      ...validUserPublic("bad_doc"),
      userId: ALICE_UID,
    })
  );
});

test("users/{uid}/contacts: owner-only contact management", async () => {
  const alice = testEnv.authenticatedContext(ALICE_UID).firestore();
  const bob = testEnv.authenticatedContext(BOB_UID).firestore();
  const ts = pastDate(10000);

  await assertSucceeds(
    alice.collection("users").doc(ALICE_UID).collection("contacts").doc(BOB_UID).set({
      userId: ALICE_UID,
      contactUid: BOB_UID,
      contactName: "Bob",
      createdAt: ts,
      updatedAt: ts,
    })
  );
  await assertSucceeds(alice.collection("users").doc(ALICE_UID).collection("contacts").get());
  await assertFails(bob.collection("users").doc(ALICE_UID).collection("contacts").get());
});

test("conversations & messages: member isolation, E2EE payloads, and query alignment", async () => {
  const alice = testEnv.authenticatedContext(ALICE_UID).firestore();
  const bob = testEnv.authenticatedContext(BOB_UID).firestore();
  const charlie = testEnv.authenticatedContext(CHARLIE_UID).firestore();
  const ts = pastDate(10000);

  const convId = "conv_alice_bob";
  await assertSucceeds(
    alice.collection("conversations").doc(convId).set({
      conversationType: "DIRECT",
      title: "Alice & Bob",
      createdBy: ALICE_UID,
      memberUids: [ALICE_UID, BOB_UID],
      adminUids: [ALICE_UID, BOB_UID],
      lastMessagePreview: "Encrypted message",
      lastMessageType: "TEXT",
      lastSenderId: ALICE_UID,
      createdAt: ts,
      updatedAt: ts,
    })
  );

  // Send E2EE message
  await assertSucceeds(
    alice.collection("conversations").doc(convId).collection("messages").doc("msg_1").set({
      conversationId: convId,
      senderId: ALICE_UID,
      senderName: "Alice",
      memberUids: [ALICE_UID, BOB_UID],
      messageType: "TEXT",
      encryptedPayload: "iv_base64:ciphertext_base64",
      encrypted: true,
      attachmentSizeBytes: 0,
      createdAt: ts,
      updatedAt: ts,
    })
  );

  // Seed a conversation Alice does NOT belong to
  await testEnv.withSecurityRulesDisabled(async (context) => {
    await context.firestore().collection("conversations").doc("conv_bob_charlie").set({
      conversationType: "DIRECT",
      title: "Bob & Charlie",
      createdBy: BOB_UID,
      memberUids: [BOB_UID, CHARLIE_UID],
      adminUids: [BOB_UID, CHARLIE_UID],
      lastMessagePreview: "Private",
      lastMessageType: "TEXT",
      lastSenderId: BOB_UID,
      createdAt: ts,
      updatedAt: ts,
    });
  });

  // Member queries with array-contains succeed; non-member Charlie is denied; unfiltered list fails
  await assertSucceeds(bob.collection("conversations").where("memberUids", "array-contains", BOB_UID).get());
  await assertSucceeds(
    bob.collection("conversations").doc(convId).collection("messages").where("memberUids", "array-contains", BOB_UID).get()
  );
  await assertFails(alice.collection("conversations").get()); // unfiltered list denied
  await assertFails(charlie.collection("conversations").doc(convId).get());
  await assertFails(
    charlie.collection("conversations").doc(convId).collection("messages").get()
  );
  await assertFails(
    charlie.collection("conversations").doc(convId).collection("messages").doc("msg_1").get()
  );

  // Bob (member) updates lastMessage metadata
  await assertSucceeds(
    bob.collection("conversations").doc(convId).update({
      lastMessagePreview: "New encrypted photo",
      lastMessageType: "IMAGE",
      lastSenderId: BOB_UID,
      updatedAt: pastDate(1000),
    })
  );

  // Immutable createdAt cannot be mutated
  await assertFails(
    alice.collection("conversations").doc(convId).update({
      createdAt: pastDate(500),
      updatedAt: pastDate(500),
    })
  );
});

test("status_updates & calls: audience isolation and terminal state locking", async () => {
  const alice = testEnv.authenticatedContext(ALICE_UID).firestore();
  const bob = testEnv.authenticatedContext(BOB_UID).firestore();
  const charlie = testEnv.authenticatedContext(CHARLIE_UID).firestore();
  const ts = pastDate(10000);

  await assertSucceeds(
    alice.collection("status_updates").doc("st_1").set({
      userId: ALICE_UID,
      authorName: "Alice",
      authorAvatarPreset: "TEAL_SHIELD",
      statusType: "TEXT",
      caption: "End-to-end encrypted!",
      backgroundHex: "#0F766E",
      audience: "PUBLIC",
      viewerUids: [],
      createdAt: ts,
      updatedAt: ts,
    })
  );
  await assertSucceeds(bob.collection("status_updates").where("audience", "==", "PUBLIC").get());

  // Call signaling + terminal state lock
  const callId = "call_1";
  await assertSucceeds(
    alice.collection("calls").doc(callId).set({
      callerId: ALICE_UID,
      callerName: "Alice",
      calleeId: BOB_UID,
      calleeName: "Bob",
      conversationId: "conv_alice_bob",
      memberUids: [ALICE_UID, BOB_UID],
      callType: "VIDEO",
      status: "RINGING",
      qualityTier: "HD_720P",
      e2eeFingerprint: "A1B2-C3D4",
      createdAt: ts,
      updatedAt: ts,
    })
  );

  // Non-participant Charlie cannot read or accept
  await assertFails(charlie.collection("calls").doc(callId).get());

  // Bob accepts, then ends the call
  await assertSucceeds(
    bob.collection("calls").doc(callId).update({
      status: "ACTIVE",
      updatedAt: pastDate(2000),
    })
  );
  await assertSucceeds(
    bob.collection("calls").doc(callId).update({
      status: "ENDED",
      updatedAt: pastDate(1000),
    })
  );

  // Terminal state lock: subsequent updates must fail
  await assertFails(
    alice.collection("calls").doc(callId).update({
      status: "ACTIVE",
      updatedAt: pastDate(500),
    })
  );
});
