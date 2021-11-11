1. In our implementation, Alice and Bob increment their Difﬁe-Hellman ratchets every time they exchange messages. Could the protocol be modiﬁed to have them increment the DH ratchets once every ten messages without compromising conﬁdentiality against an eavesdropper (i.e., semantic security)?

Since the KDF uses a unique key to generate the outputs, semantic security should still hold even when the DH ratchets are incremented every ten messages. However, break-in security would be compromised for those ten messages or until the DH ratchet is incremented again.

2. What if they never update their DH keys at all? Please explain the security consequences of this change with regard to forward secrecy and break-in recovery.

If they never update their DH keys, then break-in recovery would be compromised. Once an attacker steals one party’s sending and receiving chain keys, the attacker would be able to compute all future message keys and decrypt all future messages. So, there is no break-in recovery if the DH keys are never updated because the KDF inputs to the root chain would become constant. The symmetric-key ratchet would still provide forward secrecy.

3. The message reporting feature included in our messaging scheme is not adequate for use on an actual messaging platform. What is one shortcoming of our approach?

The message reporting feature doesn't verify the authenticity of users and messages. The adversary can fake themselves as any client to send the report, and within any report, the reported message can also be faked by the client. Therefore, the reporting feature cannot be trusted.

4. What is a way to get around the shortcoming mentioned in the previous problem?

We can verify the authenticity of user by forcing them to sign the report message with their private key, and the server will only accept those who pass the verification of their public key. Regarding fake message content, we can include a signature of the content (signed by the sender) in every header. By including the HMAC of the message, the server can verify that the message is authentic through its server log. 

5. Our messaging system relies on the platform to verify the authenticity of users’ public keys, but we are also trying to give users conﬁdentiality from the platform. Using this partial trust we place in it, how could a malicious platform learn the contents of a message one user is sending to another?

Even if end-to-end encryption is enabled, the platform can still implement the man-in-the-middle attack by faking the public keys. The platform can create 2 public keys, and send them to each of the messenger, and it passes message from one messenger to another knowing all of the plaintext. The platform can impersonate one of the recipients, intercept the message, decrypt and then encrypt the messages using their own keys, and then pass on the messages to the actual recipient. This lets them learn the content of the messages.

6. How do end-to-end encrypted messaging apps help users avoid this problem? Feel free to look this up or explore one of these messaging apps to answer this question.

   E2EE messaging apps encrypt the messages on one device such that it can only be decrypted by the recipient of the message. The message stays encrypted throughout transit, so even the platform cannot access or modify it. However, this doesn’t completely prevent man-in-the-middle attacks. We want to have some sort of endpoint authentication to ensure that the keys each end are using are actually the keys that belong to the chat participants. One method of doing this is by generating fingerprints based on the users’ public keys. The two participants check to make sure the fingerprints match, and if they match, that means that there is no man-in-the-middle attack. This authentication normally happens before the conversation through a trusted channel. For example, Signal uses safety numbers to verify the security of the messages you send to a specific contact. 