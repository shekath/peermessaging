package com.cipher.p2p

import android.app.Application
import com.cipher.p2p.crypto.PinnedProtocolStore
import com.cipher.p2p.crypto.SessionManager
import com.cipher.p2p.identity.IdentityManager
import com.cipher.p2p.invite.InviteManager
import com.cipher.p2p.security.KeystoreVault
import com.cipher.p2p.storage.SecureDatabase
import org.signal.libsignal.protocol.IdentityKey

/** Wires the security layers together. Keep this graph small and explicit. */
class CipherApp : Application() {
    lateinit var vault: KeystoreVault; private set
    lateinit var db: SecureDatabase; private set
    lateinit var identity: IdentityManager; private set
    lateinit var store: PinnedProtocolStore; private set
    lateinit var sessions: SessionManager; private set
    lateinit var invites: InviteManager; private set

    override fun onCreate() {
        super.onCreate()
        vault = KeystoreVault(this)
        db = SecureDatabase.get(this, vault)
        identity = IdentityManager(this, vault)
        store = PinnedProtocolStore(identity, db)
        sessions = SessionManager(identity, store)
        invites = InviteManager(identity, db)
    }

    /**
     * Invitee: open/scan link -> verify -> pin inviter -> send redeem request with our bundle.
     * The inviter answers with its own bundle; we then call [completeAsInvitee].
     */
    fun acceptInvite(link: String): Pair<InviteManager.InvitePayload, InviteManager.RedeemRequest> {
        val invite = invites.parseAndVerify(link)
        val inviterAddr = IdentityManager.addressOf(invite.identityKey)
        store.pinIdentity(inviterAddr, IdentityKey(invite.identityKey, 0), verifiedInPerson = false)
        return invite to invites.buildRedeem(invite, sessions.exportBundle())
    }

    fun completeAsInvitee(inviterAddress: String, inviterBundle: ByteArray) =
        sessions.startSession(inviterAddress, inviterBundle)

    /** Inviter: verify proof, burn the invite, pin the invitee, start session, reply with our bundle. */
    fun handleRedeem(req: InviteManager.RedeemRequest): ByteArray? {
        val inviteeKey = invites.verifyRedeem(req) ?: return null
        val addr = IdentityManager.addressOf(inviteeKey.serialize())
        store.pinIdentity(addr, inviteeKey, verifiedInPerson = false)
        sessions.startSession(addr, req.inviteeBundle)
        return sessions.exportBundle()
    }
}
